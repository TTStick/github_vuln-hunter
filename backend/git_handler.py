"""
Git 仓库克隆 + 项目结构扫描
"""
import os
import re
import shutil
import asyncio
import tempfile
from pathlib import Path
from typing import Optional

# 应该深度审计的源码扩展名
CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".scala",
    ".rb", ".php",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
    ".cs", ".m", ".mm", ".swift",
    ".vue", ".svelte",
}

# 应该跳过的目录
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env",
    "__pycache__", ".pytest_cache", ".mypy_cache",
    "dist", "build", "target", "out", ".next", ".nuxt", ".turbo",
    "coverage", ".coverage", ".nyc_output",
    "vendor", "third_party", "third-party", "deps",
    ".idea", ".vscode", ".gradle",
    "test", "tests", "__tests__", "spec", "specs", "fixtures", "e2e", "cypress",
    "test-utils", "test_utils", "testing", "mocks", "__mocks__",
    "integration-tests", "integration_tests", "unit-tests", "unit_tests",
    "evals", "eval", "benchmarks", "benchmark",
    "docs", "doc", "examples", "example", "samples", "demos", "demo",
    "migrations", "locale", "i18n", "translations",
    "public", "static", "assets",  # 通常是前端静态资源
    "bin",
}

# 文件名匹配（基名）—— 也跳过
SKIP_FILE_PATTERNS = (
    ".min.js", ".min.css", ".bundle.js", ".bundle.css",
    ".d.ts", ".d.cts", ".d.mts",   # 类型声明
    "-lock.json", "-lock.yaml",
    ".snap",                        # 快照
    ".pb.go", "_pb.py", "_pb2.py",  # protobuf 生成代码
    ".generated.go", ".gen.go",
    # 测试文件（混在源码目录里的）
    ".test.ts", ".test.tsx", ".test.js", ".test.jsx", ".test.mjs",
    ".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx",
    "_test.go", "_test.py",
    ".eval.ts", ".eval.js",        # 评估脚本
    ".stories.ts", ".stories.tsx", ".stories.js",  # storybook
)

# 安全敏感关键词（用于启发式选文件）—— 命中越多分越高
RISK_KEYWORDS = {
    # 高权重（强相关）
    "exec": 5, "eval": 5, "shell": 5, "subprocess": 5, "spawn": 4, "system": 4,
    "deserial": 5, "pickle": 4, "unmarshal": 3, "yaml": 3,
    "auth": 4, "login": 4, "session": 3, "token": 3, "jwt": 3, "oauth": 3, "password": 3,
    "upload": 4, "download": 3, "filepath": 3, "filesystem": 3, "fs.": 2,
    "sql": 4, "query": 3, "db": 2, "database": 2, "mysql": 3, "postgres": 3, "sqlite": 2,
    "request": 2, "fetch": 2, "http": 2, "axios": 2, "url": 2, "redirect": 3,
    "admin": 3, "permission": 3, "rbac": 3, "role": 2, "policy": 2,
    "route": 3, "router": 3, "handler": 3, "controller": 3, "endpoint": 3, "api": 2,
    "parse": 2, "deserialize": 4, "serialize": 1,
    "command": 3, "cmd": 2, "rpc": 2, "grpc": 2,
    "crypto": 3, "cipher": 3, "hash": 2, "decrypt": 3, "encrypt": 2, "secret": 2,
    "xml": 3, "ssrf": 5, "xxe": 5, "template": 2, "render": 2,
    "middleware": 2, "validate": 2, "sanitize": 2, "escape": 1,
    "config": 1, "env": 1,
}

# 路径中包含这些关键词的目录加分（按目录粗筛时使用）
RISK_DIR_HINTS = {
    "auth": 4, "login": 4, "session": 3, "user": 2, "account": 2,
    "api": 3, "route": 3, "router": 3, "handler": 3, "controller": 3,
    "upload": 4, "download": 3, "file": 2,
    "admin": 3, "permission": 3, "rbac": 3, "policy": 2,
    "server": 2, "backend": 2, "service": 1,
    "middleware": 2, "guard": 2, "interceptor": 2,
    "crypto": 3, "security": 4, "sso": 3, "saml": 3, "oidc": 3,
    "query": 3, "db": 2, "database": 2, "storage": 2, "store": 1,
    "rpc": 2, "grpc": 2, "graphql": 3,
    "command": 3, "exec": 4, "shell": 4,
    "parser": 3, "deserial": 4,
}

MAX_FILE_BYTES = 200 * 1024  # 单文件最大 200KB


async def clone_repo(repo_url: str, target_dir: Path,
                     timeout: int = 300) -> tuple[bool, str]:
    """浅克隆。返回 (success, message)。"""
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    if target_dir.exists():
        shutil.rmtree(target_dir)
    cmd = ["git", "clone", "--depth", "1", "--single-branch", repo_url, str(target_dir)]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return False, "git clone timed out"
    if proc.returncode != 0:
        return False, stderr.decode("utf-8", errors="ignore")[-400:]
    return True, "ok"


def build_file_tree(root: Path, max_depth: int = 8) -> tuple[str, list[Path]]:
    """生成给 LLM 看的扁平文件清单 + 返回所有可分析文件路径。"""
    root = root.resolve()
    files: list[Path] = []
    lines: list[str] = []

    def walk(p: Path, depth: int):
        if depth > max_depth:
            return
        try:
            entries = sorted(p.iterdir(), key=lambda x: (x.is_file(), x.name))
        except (PermissionError, OSError):
            return
        for entry in entries:
            if entry.name.startswith("."):
                if entry.name not in {".env.example", ".github"}:
                    continue
            if entry.is_dir():
                if entry.name.lower() in SKIP_DIRS:
                    continue
                walk(entry, depth + 1)
            else:
                try:
                    size = entry.stat().st_size
                except OSError:
                    continue
                if size > MAX_FILE_BYTES:
                    continue
                name_lower = entry.name.lower()
                # 跳过生成代码、压缩资源、声明文件、快照等
                if any(name_lower.endswith(suf) for suf in SKIP_FILE_PATTERNS):
                    continue
                rel = entry.relative_to(root)
                if entry.suffix.lower() in CODE_EXTENSIONS:
                    files.append(entry)
                    lines.append(f"{rel}  ({size}B)")
                elif entry.name in {
                    "Dockerfile", "Makefile", "requirements.txt", "package.json",
                    "go.mod", "Cargo.toml", "pom.xml", "build.gradle",
                    "composer.json", "Gemfile",
                }:
                    lines.append(f"{rel}  ({size}B)  [config]")

    walk(root, 0)
    return "\n".join(lines), files


def score_file_riskiness(rel_path: str) -> tuple[int, list[str]]:
    """根据文件路径关键词打分。返回 (score, hit_keywords)。"""
    p = rel_path.lower().replace("\\", "/")
    score = 0
    hits = []
    for kw, weight in RISK_KEYWORDS.items():
        if kw in p:
            score += weight
            hits.append(kw)
    # 路径越浅（更可能是入口）小幅加分
    depth = p.count("/")
    if depth <= 2:
        score += 1
    return score, hits


def build_compact_tree(files: list[Path], root: Path, char_budget: int = 11000) -> str:
    """
    为大仓库构建按目录折叠的紧凑视图。每个目录显示文件总数 + 优先列出
    高风险评分的文件，超出预算就只列目录摘要。
    """
    root = root.resolve()
    # 按一级 / 二级目录分组
    by_dir: dict[str, list[tuple[str, int, list[str]]]] = {}
    for f in files:
        rel = str(f.relative_to(root)).replace("\\", "/")
        parts = rel.split("/")
        if len(parts) == 1:
            group = "."
        elif len(parts) == 2:
            group = parts[0]
        else:
            group = "/".join(parts[:2])
        score, hits = score_file_riskiness(rel)
        by_dir.setdefault(group, []).append((rel, score, hits))

    # 按"目录内最高分"排序，让高风险目录先出现
    dir_max = {d: max((s for _, s, _ in lst), default=0) for d, lst in by_dir.items()}
    sorted_dirs = sorted(by_dir.keys(), key=lambda d: -dir_max[d])

    out: list[str] = []
    used = 0
    for d in sorted_dirs:
        entries = sorted(by_dir[d], key=lambda x: -x[1])
        header = f"\n[{d}/]  ({len(entries)} files)"
        if used + len(header) > char_budget:
            out.append(f"\n... [{len(sorted_dirs) - sorted_dirs.index(d)} more dirs omitted] ...")
            break
        out.append(header)
        used += len(header)
        # 每个目录最多列 15 个文件，优先高分
        keep = entries[:15]
        for rel, score, hits in keep:
            tag = f"  *risk={score}" if score >= 3 else ""
            line = f"\n  {rel}{tag}"
            if used + len(line) > char_budget:
                out.append(f"\n  ... [{len(entries) - keep.index((rel, score, hits))} more files in {d}/]")
                break
            out.append(line)
            used += len(line)
        if len(entries) > 15:
            extra = f"\n  ... [{len(entries) - 15} more files in {d}/]"
            if used + len(extra) <= char_budget:
                out.append(extra)
                used += len(extra)
    return "".join(out)


def directory_summary(files: list[Path], root: Path, top_n: int = 40) -> list[dict]:
    """
    用于"目录优先"的两段式 triage：返回带评分的目录摘要列表。
    """
    root = root.resolve()
    by_dir: dict[str, dict] = {}
    for f in files:
        rel = str(f.relative_to(root)).replace("\\", "/")
        parts = rel.split("/")
        if len(parts) == 1:
            d = "."
        else:
            # 用两级目录粒度（避免 packages/cli vs packages/core 合并）
            d = "/".join(parts[:2]) if len(parts) >= 2 else parts[0]
        score, hits = score_file_riskiness(rel)
        if d not in by_dir:
            by_dir[d] = {"path": d, "file_count": 0, "max_risk": 0, "kw_hits": set()}
        by_dir[d]["file_count"] += 1
        by_dir[d]["max_risk"] = max(by_dir[d]["max_risk"], score)
        for kw in hits:
            by_dir[d]["kw_hits"].add(kw)

    # 目录名本身的关键词加分
    for d, info in by_dir.items():
        for kw, w in RISK_DIR_HINTS.items():
            if kw in d.lower():
                info["max_risk"] += w
                info["kw_hits"].add(f"~{kw}")

    out = []
    for info in sorted(by_dir.values(), key=lambda x: -x["max_risk"]):
        out.append({
            "path": info["path"],
            "file_count": info["file_count"],
            "risk_score": info["max_risk"],
            "keywords": sorted(info["kw_hits"])[:8],
        })
    return out[:top_n]


def files_in_dirs(files: list[Path], root: Path, dirs: list[str]) -> list[Path]:
    """筛选出在指定目录前缀下的文件。"""
    root = root.resolve()
    norm_dirs = [d.strip("./").replace("\\", "/").rstrip("/") for d in dirs if d]
    out = []
    for f in files:
        rel = str(f.relative_to(root)).replace("\\", "/")
        if any(rel == nd or rel.startswith(nd + "/") for nd in norm_dirs):
            out.append(f)
    return out


def heuristic_pick_files(files: list[Path], root: Path, top_n: int = 25) -> list[dict]:
    """
    启发式兜底：当 LLM triage 返回 0 文件时使用。按文件名关键词打分挑选。
    """
    root = root.resolve()
    scored = []
    for f in files:
        rel = str(f.relative_to(root)).replace("\\", "/")
        score, hits = score_file_riskiness(rel)
        if score >= 2:
            scored.append({
                "path": rel,
                "score": score,
                "hits": hits,
                "abs": f,
            })
    scored.sort(key=lambda x: -x["score"])
    return scored[:top_n]


def detect_metadata(root: Path) -> dict:
    """从配置文件推断语言/框架。也扫描 monorepo 的子包。"""
    meta = {"languages": [], "frameworks": [], "manifest_excerpts": {}, "monorepo": False}
    candidates = {
        "package.json": "javascript/typescript",
        "requirements.txt": "python",
        "pyproject.toml": "python",
        "go.mod": "go",
        "Cargo.toml": "rust",
        "pom.xml": "java",
        "build.gradle": "java/kotlin",
        "composer.json": "php",
        "Gemfile": "ruby",
    }
    for fname, lang in candidates.items():
        p = root / fname
        if p.exists():
            if lang not in meta["languages"]:
                meta["languages"].append(lang)
            try:
                meta["manifest_excerpts"][fname] = p.read_text(errors="ignore")[:2000]
            except OSError:
                pass

    # monorepo 探测：扫描 packages/* apps/* libs/* 下的 package.json / pyproject.toml
    monorepo_globs = ["packages/*", "apps/*", "libs/*", "services/*", "crates/*"]
    sub_manifests = []
    for pattern in monorepo_globs:
        for sub in root.glob(pattern):
            if sub.is_dir() and sub.name.lower() not in SKIP_DIRS:
                for fname in ["package.json", "pyproject.toml", "go.mod", "Cargo.toml"]:
                    p = sub / fname
                    if p.exists():
                        try:
                            sub_manifests.append(f"# {sub.name}/{fname}\n" + p.read_text(errors="ignore")[:800])
                        except OSError:
                            pass
                        if fname in candidates and candidates[fname] not in meta["languages"]:
                            meta["languages"].append(candidates[fname])
    if sub_manifests:
        meta["monorepo"] = True
        meta["manifest_excerpts"]["sub_packages"] = "\n\n".join(sub_manifests[:10])

    # 尝试猜框架（简易关键词）
    blob = " ".join(meta["manifest_excerpts"].values()).lower()
    fw_keywords = {
        "flask": "flask", "django": "django", "fastapi": "fastapi", "starlette": "starlette",
        "tornado": "tornado", "aiohttp": "aiohttp",
        "express": "express", "next": "next.js", "react": "react", "vue": "vue",
        "nestjs": "nestjs", "koa": "koa", "hapi": "hapi", "fastify": "fastify",
        "spring": "spring", "rails": "rails", "laravel": "laravel", "symfony": "symfony",
        "gin-gonic": "gin", "echo": "echo", "fiber": "fiber",
        "axum": "axum", "actix": "actix", "rocket": "rocket",
        "graphql": "graphql", "grpc": "grpc",
    }
    for kw, fw in fw_keywords.items():
        if kw in blob and fw not in meta["frameworks"]:
            meta["frameworks"].append(fw)
    return meta


def read_file_with_lines(path: Path, max_lines: int = 800) -> tuple[str, int]:
    """读取文件，按行号注释；超长截断。返回 (annotated_text, total_lines)。"""
    try:
        text = path.read_text(errors="ignore")
    except OSError:
        return "", 0
    lines = text.splitlines()
    total = len(lines)
    if total > max_lines:
        # 截断时保留头部 + 末尾两段，并明确标注
        head = max_lines * 3 // 4
        tail = max_lines - head
        head_lines = lines[:head]
        tail_start = total - tail
        tail_lines = lines[tail_start:]
        annotated = []
        for i, line in enumerate(head_lines, start=1):
            annotated.append(f"{i:5d}  {line}")
        annotated.append(f"... [truncated {tail_start - head} lines] ...")
        for i, line in enumerate(tail_lines, start=tail_start + 1):
            annotated.append(f"{i:5d}  {line}")
        return "\n".join(annotated), total
    annotated = "\n".join(f"{i:5d}  {line}" for i, line in enumerate(lines, start=1))
    return annotated, total


def extract_snippet(path: Path, line_start: Optional[int], line_end: Optional[int],
                    context: int = 3) -> str:
    """根据 finding 的行号，取代码片段（带上下文）。"""
    if not line_start:
        return ""
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return ""
    s = max(1, line_start - context)
    e = min(len(lines), (line_end or line_start) + context)
    out = []
    for i in range(s, e + 1):
        marker = ">> " if line_start <= i <= (line_end or line_start) else "   "
        out.append(f"{marker}{i:5d}  {lines[i-1]}")
    return "\n".join(out)


def cleanup_repo(path: Path):
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def workspace_dir() -> Path:
    d = Path(__file__).parent.parent / "data" / "repos"
    d.mkdir(parents=True, exist_ok=True)
    return d
