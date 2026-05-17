"""
漏洞挖掘流水线 —— 这是整个工具的大脑。

阶段:
  1. clone       - 克隆仓库
  2. recon       - 扫描文件结构 + 语言/框架探测
  3. triage      - LLM 规划重点文件（项目理解）
  4. scan        - 对每个高风险文件做漏洞检测
  5. self_verify - 同一模型质疑自己的发现（第一道防幻觉）
  6. cross_review- 用 review_config（可不同模型）二次审（第二道防幻觉）
  7. report      - 生成可提交的 Markdown 修复文档

冗余机制：
  - 每个 finding 必须经过 self_verify 和 cross_review 才会被保留
  - 任一阶段 verdict 为 rejected -> finding 被淘汰但仍记录在数据库（status=rejected）
  - 引用的代码片段会和原文件二次核对，无法对齐则丢弃（杜绝幻觉行号）
  - 信心度 < 0.4 自动淘汰
"""
import asyncio
import json
import time
from pathlib import Path
from typing import Optional

import database
import git_handler
import llm_providers
import prompts


# 防止 LLM 一次性吃下整个项目，对单项目限制文件数
MAX_FILES_TO_SCAN = 25
MIN_CONFIDENCE = 0.4


def _collapse_ws(s: str) -> str:
    """折叠所有连续空白字符为单个空格，用于鲁棒的代码片段匹配。"""
    import re
    return re.sub(r"\s+", " ", s).strip()


class Pipeline:
    def __init__(self, project: dict):
        self.project = project
        self.project_id = project["id"]
        self.repo_dir: Optional[Path] = None
        self.scanner: Optional[llm_providers.LLMClient] = None  # 主分析模型
        self.reviewer: Optional[llm_providers.LLMClient] = None  # 交叉验证模型
        self.project_summary: str = ""
        self.metadata: dict = {}

    # ---- 日志 / 进度小工具 ----
    async def log(self, level: str, stage: str, msg: str):
        await database.add_log(self.project_id, level, stage, msg)

    async def set_stage(self, stage: str, progress: float):
        await database.update_project(self.project_id, stage=stage, progress=progress)
        await self.log("stage", stage, f"=> entering stage: {stage} ({progress:.1f}%)")

    # ---- 主入口 ----
    async def run(self):
        try:
            await database.update_project(
                self.project_id, status="cloning",
                started_at=int(time.time()), progress=1.0
            )
            await self._stage_clone()

            await database.update_project(self.project_id, status="analyzing")
            self.scanner = await llm_providers.make_client(self.project["llm_config_id"])
            self.reviewer = await llm_providers.make_client(self.project["review_config_id"])

            recon = await self._stage_recon()
            triage = await self._stage_triage(recon)
            raw_findings = await self._stage_scan(triage)
            verified = await self._stage_self_verify(raw_findings)
            confirmed = await self._stage_cross_review(verified)
            await self._stage_report(confirmed)

            await database.update_project(
                self.project_id, status="done",
                finished_at=int(time.time()), progress=100.0,
                stage="completed",
            )
            await self.log("info", "done", f"Analysis complete. Confirmed findings: {len(confirmed)}")
        except Exception as e:
            await self.log("error", "fatal", f"Pipeline error: {e!r}")
            await database.update_project(
                self.project_id, status="failed",
                finished_at=int(time.time()),
                error=str(e)[:500],
            )
            raise
        finally:
            if self.repo_dir:
                git_handler.cleanup_repo(self.repo_dir)

    # ---- 1. 克隆 ----
    async def _stage_clone(self):
        await self.set_stage("clone", 2.0)
        repo_url = self.project["repo_url"]
        target = git_handler.workspace_dir() / f"proj_{self.project_id}"
        await self.log("info", "clone", f"Cloning {repo_url} ...")
        ok, msg = await git_handler.clone_repo(repo_url, target)
        if not ok:
            raise RuntimeError(f"git clone failed: {msg}")
        self.repo_dir = target
        await self.log("info", "clone", f"Clone OK at {target}")

    # ---- 2. 侦察 ----
    async def _stage_recon(self) -> dict:
        await self.set_stage("recon", 8.0)
        tree, files = git_handler.build_file_tree(self.repo_dir)
        meta = git_handler.detect_metadata(self.repo_dir)
        self.metadata = meta
        await database.update_project(self.project_id, files_total=len(files))
        await self.log(
            "info", "recon",
            f"Discovered {len(files)} source files. Languages: {meta['languages']}. "
            f"Frameworks: {meta['frameworks']}",
        )
        return {"file_tree": tree, "files": files, "metadata": meta}

    # ---- 3. 分类 ----
    async def _stage_triage(self, recon: dict) -> list[dict]:
        await self.set_stage("triage", 15.0)
        files: list[Path] = recon["files"]
        meta = recon["metadata"]
        total = len(files)

        # 小仓库走单遍 triage；大仓库 / monorepo 走两遍（目录→文件）
        LARGE_REPO_THRESHOLD = 300
        is_large = total > LARGE_REPO_THRESHOLD or meta.get("monorepo")

        candidate_files: list[Path]
        if is_large:
            await self.log(
                "info", "triage",
                f"Large repo detected ({total} files, monorepo={meta.get('monorepo', False)}). "
                f"Running two-pass directory→file triage.",
            )
            candidate_files = await self._triage_pick_dirs(files, meta)
            if not candidate_files:
                await self.log("warn", "triage",
                               "Directory triage returned no usable dirs, falling back to whole repo.")
                candidate_files = files
        else:
            candidate_files = files

        # ---- 让模型从候选文件中挑高风险文件 ----
        targets = await self._triage_pick_files(candidate_files, meta)

        # 启发式兜底：模型挑了 0 / 极少时，按关键词评分补
        if len(targets) < 3:
            await self.log(
                "warn", "triage",
                f"Model selected only {len(targets)} file(s); applying heuristic fallback.",
            )
            heuristic = git_handler.heuristic_pick_files(files, self.repo_dir, top_n=MAX_FILES_TO_SCAN)
            existing_paths = {t["rel_path"] for t in targets}
            for h in heuristic:
                if h["path"] in existing_paths:
                    continue
                targets.append({
                    "rel_path": h["path"],
                    "abs_path": h["abs"],
                    "reason": f"heuristic match (keywords: {', '.join(h['hits'][:5])}, score={h['score']})",
                    "vuln_classes": [],  # 让 scan 阶段自由判断
                })
                if len(targets) >= MAX_FILES_TO_SCAN:
                    break
            await self.log("info", "triage",
                           f"After heuristic fallback: {len(targets)} target files.")

        targets = targets[:MAX_FILES_TO_SCAN]
        await self.log("info", "triage",
                       f"Selected {len(targets)} high-risk files for deep scan.")
        for t in targets:
            cls = ", ".join(t.get("vuln_classes", [])) or "any"
            await self.log("info", "triage", f"  - {t['rel_path']} ({cls}) :: {t['reason']}")
        return targets

    async def _triage_pick_dirs(self, files: list[Path], meta: dict) -> list[Path]:
        """大仓库第一遍：让模型从目录摘要里挑值得深扫的子目录。"""
        await database.update_project(self.project_id, progress=17.0)
        dir_summary = git_handler.directory_summary(files, self.repo_dir, top_n=50)
        summary_text = "\n".join(
            f"  {d['path']:<45}  files={d['file_count']:<4}  risk={d['risk_score']:<3}  kw={','.join(d['keywords'])}"
            for d in dir_summary
        )

        prompt = prompts.TRIAGE_DIRS_PROMPT.format(
            dir_summary=summary_text,
            metadata=json.dumps(meta, indent=2)[:3000],
            max_dirs=8,
        )
        try:
            text = await self.scanner.chat(
                [
                    {"role": "system", "content": "You output ONLY valid JSON. No prose, no markdown fences."},
                    {"role": "user", "content": prompt},
                ],
                project_id=self.project_id,
                stage="triage",
                json_mode=True,
            )
        except Exception as e:
            await self.log("warn", "triage", f"Directory triage LLM error: {e}")
            return []

        parsed = llm_providers.extract_json(text) or {}
        self.project_summary = parsed.get("project_summary", "(no summary)")
        await self.log("info", "triage", f"Project summary: {self.project_summary}")

        selected = parsed.get("selected_dirs", [])
        if not selected:
            return []
        dir_paths = [s.get("path", "") for s in selected if s.get("path")]
        await self.log("info", "triage",
                       f"Chose {len(dir_paths)} directories: {', '.join(dir_paths)}")
        chosen_files = git_handler.files_in_dirs(files, self.repo_dir, dir_paths)
        await self.log("info", "triage",
                       f"  -> {len(chosen_files)} files in chosen dirs (out of {len(files)} total)")
        return chosen_files

    async def _triage_pick_files(self, files: list[Path], meta: dict) -> list[dict]:
        """让模型从（已过滤的）文件列表里挑高风险文件。"""
        if not files:
            return []
        await database.update_project(self.project_id, progress=21.0)
        # 用 compact tree 表示，已带 risk hint，更容易让模型选对
        tree = git_handler.build_compact_tree(files, self.repo_dir, char_budget=11000)

        prompt = prompts.TRIAGE_PROMPT.format(
            file_tree=tree,
            metadata=json.dumps(meta, indent=2)[:2500],
            max_files=MAX_FILES_TO_SCAN,
        )
        try:
            text = await self.scanner.chat(
                [
                    {"role": "system", "content": "You output ONLY valid JSON. No prose, no markdown fences."},
                    {"role": "user", "content": prompt},
                ],
                project_id=self.project_id,
                stage="triage",
                json_mode=True,
            )
        except Exception as e:
            await self.log("warn", "triage", f"File triage LLM error: {e}")
            return []

        parsed = llm_providers.extract_json(text) or {}
        # project_summary 已经在 dir-pass 里设过；如果是小仓库单遍，这里设
        if not self.project_summary or self.project_summary == "(no summary)":
            self.project_summary = parsed.get("project_summary", "(no summary)")
            await self.log("info", "triage", f"Project summary: {self.project_summary}")

        high_risk = parsed.get("high_risk_files", [])
        if not high_risk:
            await self.log("warn", "triage", "Model returned empty high_risk_files array.")
            return []

        # 健壮的路径匹配
        available: dict[str, Path] = {}
        for f in files:
            rel = str(f.relative_to(self.repo_dir)).replace("\\", "/")
            available[rel] = f
            # 也建一份小写索引以应对大小写差异
            available[rel.lower()] = f

        targets = []
        seen_abs = set()
        dropped = 0
        for item in high_risk:
            raw = (item.get("path") or "").strip().replace("\\", "/")
            # 去掉常见前缀
            for prefix in ("./", "/"):
                if raw.startswith(prefix):
                    raw = raw[len(prefix):]
            abs_path = available.get(raw) or available.get(raw.lower())
            if not abs_path:
                # 后缀匹配
                candidates = [
                    v for k, v in available.items()
                    if k.endswith(raw) or k.endswith(raw.lower())
                ]
                if candidates:
                    abs_path = candidates[0]
            if not abs_path:
                dropped += 1
                continue
            if str(abs_path) in seen_abs:
                continue
            seen_abs.add(str(abs_path))
            rel_path = str(abs_path.relative_to(self.repo_dir)).replace("\\", "/")
            targets.append({
                "rel_path": rel_path,
                "abs_path": abs_path,
                "reason": item.get("reason", ""),
                "vuln_classes": item.get("vuln_classes", []),
            })

        if dropped:
            await self.log("warn", "triage",
                           f"Dropped {dropped} file(s) from model output: path did not match any real file.")
        return targets

    # ---- 4. 深度扫描 ----
    async def _stage_scan(self, targets: list[dict]) -> list[dict]:
        await self.set_stage("scan", 25.0)
        all_findings = []
        n = len(targets)
        for idx, tgt in enumerate(targets):
            progress = 25.0 + (45.0 - 25.0) * (idx / max(n, 1))
            await database.update_project(self.project_id, progress=progress, files_scanned=idx)

            content, total_lines = git_handler.read_file_with_lines(tgt["abs_path"])
            if not content:
                continue

            prompt = prompts.SCAN_PROMPT.format(
                file_path=tgt["rel_path"],
                project_summary=self.project_summary,
                vuln_classes=", ".join(tgt["vuln_classes"]) or "any",
                file_content=content,
            )
            try:
                text = await self.scanner.chat(
                    [
                        {"role": "system", "content": "You output ONLY valid JSON."},
                        {"role": "user", "content": prompt},
                    ],
                    project_id=self.project_id, stage="scan", json_mode=True,
                )
            except Exception as e:
                await self.log("warn", "scan", f"LLM error on {tgt['rel_path']}: {e}")
                continue

            parsed = llm_providers.extract_json(text) or {}
            findings = parsed.get("findings", [])
            # 给每个 finding 补充文件信息
            file_text_cache = None
            for f in findings:
                f["file_path"] = tgt["rel_path"]
                f["_abs_path"] = str(tgt["abs_path"])
                f["discovery_reasoning"] = f.get("reasoning") or ""
                # 防幻觉：核对代码片段是否真的存在
                snippet = f.get("code_snippet", "").strip()
                if snippet:
                    if file_text_cache is None:
                        file_text_cache = tgt["abs_path"].read_text(errors="ignore")
                    # 归一化：折叠所有空白后做子串匹配，比 replace("    ","") 鲁棒得多
                    norm_src = _collapse_ws(file_text_cache)
                    # 取片段中第一条非空的"实质性"行（>10 字符的代码行）
                    pivot = ""
                    for line in snippet.splitlines():
                        s = line.strip()
                        if len(s) > 10 and not s.startswith(("//", "#", "/*", "*")):
                            pivot = s
                            break
                    if not pivot:
                        # 退而求其次：把整段 snippet 折叠后去匹配
                        pivot = _collapse_ws(snippet)[:80]
                    norm_pivot = _collapse_ws(pivot)
                    f["_snippet_aligned"] = bool(norm_pivot and norm_pivot in norm_src)
                else:
                    f["_snippet_aligned"] = False
            all_findings.extend(findings)
            await self.log(
                "info", "scan",
                f"[{idx+1}/{n}] {tgt['rel_path']}: {len(findings)} potential findings",
            )

        await database.update_project(
            self.project_id, files_scanned=n, raw_findings=len(all_findings),
        )
        await self.log("info", "scan", f"Deep scan complete. Raw findings: {len(all_findings)}")
        return all_findings

    # ---- 5. 自验证 (防幻觉 round 1) ----
    async def _stage_self_verify(self, raw_findings: list[dict]) -> list[dict]:
        await self.set_stage("self_verify", 50.0)
        verified = []
        n = len(raw_findings)
        for idx, f in enumerate(raw_findings):
            progress = 50.0 + (70.0 - 50.0) * (idx / max(n, 1))
            await database.update_project(self.project_id, progress=progress)

            # 信心阈值 / 代码片段对齐 这两道前置闸口
            if f.get("confidence", 0.5) < MIN_CONFIDENCE:
                await self.log("info", "self_verify",
                               f"Skip low-confidence finding {f.get('title','?')[:60]}")
                continue
            if f.get("_snippet_aligned") is False:
                await self.log("warn", "self_verify",
                               f"Reject hallucinated snippet: {f.get('title','?')[:60]}")
                f["status"] = "rejected"
                f["rejected_reason"] = "code snippet not found in actual file (likely hallucination)"
                await self._save_finding(f)
                continue

            abs_path = Path(f["_abs_path"])
            content, _ = git_handler.read_file_with_lines(abs_path)
            prompt = prompts.SELF_VERIFY_PROMPT.format(
                vuln_type=f.get("vuln_type", "unknown"),
                file_path=f["file_path"],
                line_start=f.get("line_start", "?"),
                line_end=f.get("line_end", "?"),
                title=f.get("title", ""),
                discovery_reasoning=f.get("discovery_reasoning", ""),
                exploit_scenario=f.get("exploit_scenario", ""),
                data_flow=json.dumps(f.get("data_flow", [])),
                file_content=content,
            )
            try:
                text = await self.scanner.chat(
                    [
                        {"role": "system", "content": "You output ONLY valid JSON. Be ruthlessly skeptical."},
                        {"role": "user", "content": prompt},
                    ],
                    project_id=self.project_id, stage="self_verify", json_mode=True,
                )
            except Exception as e:
                await self.log("warn", "self_verify", f"LLM error: {e}")
                continue
            verdict_obj = llm_providers.extract_json(text) or {}
            verdict = verdict_obj.get("verdict", "uncertain")
            f["verification_reasoning"] = verdict_obj.get("reasoning", "")
            f["_verify_confidence"] = verdict_obj.get("confidence", 0.0)
            if verdict_obj.get("severity_adjusted"):
                f["severity"] = verdict_obj["severity_adjusted"]
            if verdict_obj.get("adjusted_title"):
                f["title"] = verdict_obj["adjusted_title"]

            if verdict == "confirmed" and verdict_obj.get("confidence", 0) >= MIN_CONFIDENCE:
                verified.append(f)
                await self.log("info", "self_verify",
                               f"OK [{verdict_obj.get('confidence',0):.2f}] {f.get('title','?')[:80]}")
            else:
                f["status"] = "rejected"
                f["rejected_reason"] = f"self_verify={verdict}: {verdict_obj.get('reasoning','')[:200]}"
                await self._save_finding(f)
                await self.log("info", "self_verify",
                               f"DROP [{verdict}] {f.get('title','?')[:80]}")

        await self.log("info", "self_verify",
                       f"Survived self-verify: {len(verified)} / {n}")
        return verified

    # ---- 6. 交叉验证 (防幻觉 round 2) ----
    async def _stage_cross_review(self, verified: list[dict]) -> list[dict]:
        await self.set_stage("cross_review", 72.0)
        confirmed = []
        n = len(verified)
        for idx, f in enumerate(verified):
            progress = 72.0 + (90.0 - 72.0) * (idx / max(n, 1))
            await database.update_project(self.project_id, progress=progress)

            abs_path = Path(f["_abs_path"])
            content, _ = git_handler.read_file_with_lines(abs_path)
            prompt = prompts.CROSS_REVIEW_PROMPT.format(
                vuln_type=f.get("vuln_type", "unknown"),
                file_path=f["file_path"],
                line_start=f.get("line_start", "?"),
                line_end=f.get("line_end", "?"),
                title=f.get("title", ""),
                discovery_reasoning=f.get("discovery_reasoning", ""),
                verification_reasoning=f.get("verification_reasoning", ""),
                data_flow=json.dumps(f.get("data_flow", [])),
                exploit_scenario=f.get("exploit_scenario", ""),
                file_content=content,
            )
            try:
                text = await self.reviewer.chat(
                    [
                        {"role": "system", "content": "You output ONLY valid JSON. You are the final gate."},
                        {"role": "user", "content": prompt},
                    ],
                    project_id=self.project_id, stage="cross_review", json_mode=True,
                )
            except Exception as e:
                await self.log("warn", "cross_review", f"LLM error: {e}")
                continue
            verdict_obj = llm_providers.extract_json(text) or {}
            verdict = verdict_obj.get("final_verdict", "rejected")
            f["cross_review_reasoning"] = verdict_obj.get("reasoning", "")
            f["_exploit_sketch"] = verdict_obj.get("exploit_sketch", "")
            f["_real_impact"] = verdict_obj.get("real_impact", "")
            if verdict_obj.get("real_severity"):
                f["severity"] = verdict_obj["real_severity"]

            # 综合信心
            c1 = f.get("confidence", 0.5)
            c2 = f.get("_verify_confidence", 0.5)
            c3 = verdict_obj.get("confidence", 0.0)
            f["confidence"] = round((c1 + c2 + c3) / 3, 3)

            if verdict == "confirmed" and f["confidence"] >= MIN_CONFIDENCE:
                confirmed.append(f)
                await self.log("info", "cross_review",
                               f"PASS [{f['confidence']:.2f}] {f.get('title','?')[:80]}")
            else:
                f["status"] = "rejected"
                f["rejected_reason"] = f"cross_review={verdict}: {verdict_obj.get('reasoning','')[:200]}"
                await self._save_finding(f)
                await self.log("info", "cross_review",
                               f"REJECT [{verdict}] {f.get('title','?')[:80]}")

        await database.update_project(
            self.project_id,
            confirmed_findings=len(confirmed),
        )
        # rejected 计数
        proj = await database.get_project(self.project_id)
        raw = proj.get("raw_findings", 0)
        await database.update_project(
            self.project_id, rejected_findings=max(0, raw - len(confirmed)),
        )
        await self.log("info", "cross_review",
                       f"Final confirmed: {len(confirmed)} / {n}")
        return confirmed

    # ---- 7. 报告 ----
    async def _stage_report(self, confirmed: list[dict]):
        await self.set_stage("report", 92.0)
        repo_name = self.project.get("repo_name", "")
        for idx, f in enumerate(confirmed):
            abs_path = Path(f["_abs_path"])
            snippet = git_handler.extract_snippet(
                abs_path, f.get("line_start"), f.get("line_end"), context=4,
            )
            f["code_snippet"] = snippet or f.get("code_snippet", "")
            prompt = prompts.REPORT_PROMPT.format(
                vuln_type=f.get("vuln_type", "unknown"),
                severity=f.get("severity", "medium"),
                file_path=f["file_path"],
                line_start=f.get("line_start", "?"),
                line_end=f.get("line_end", "?"),
                title=f.get("title", ""),
                repo_name=repo_name,
                discovery_reasoning=f.get("discovery_reasoning", ""),
                verification_reasoning=f.get("verification_reasoning", ""),
                cross_review_reasoning=f.get("cross_review_reasoning", ""),
                exploit_sketch=f.get("_exploit_sketch", ""),
                real_impact=f.get("_real_impact", ""),
                code_snippet=snippet,
            )
            try:
                md = await self.scanner.chat(
                    [
                        {"role": "system",
                         "content": "You write professional vulnerability disclosure reports in Markdown."},
                        {"role": "user", "content": prompt},
                    ],
                    project_id=self.project_id, stage="report",
                )
            except Exception as e:
                md = f"# Report generation failed: {e}\n\nRaw data: {json.dumps(f, default=str)[:1000]}"
            f["full_report_md"] = md
            f["fix_suggestion"] = md  # 兼容字段
            f["status"] = "confirmed"
            await self._save_finding(f)

    async def _save_finding(self, f: dict):
        # 清掉内部用字段
        save = dict(f)
        for k in list(save.keys()):
            if k.startswith("_"):
                del save[k]
        await database.add_finding(self.project_id, save)


async def run_pipeline_for_project(project_id: int):
    """Worker 入口。"""
    proj = await database.get_project(project_id)
    if not proj:
        return
    pl = Pipeline(proj)
    await pl.run()
