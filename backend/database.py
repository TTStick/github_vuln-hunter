"""
SQLite 持久化层
表结构:
  projects        - 待分析/已分析的 GitHub 项目
  scan_logs       - 每个项目的分析过程日志（流水线每一步）
  findings        - 最终确认的漏洞发现
  api_usage       - LLM API 调用统计（计费/性能/错误率）
  llm_configs     - 用户配置的 LLM 端点（多套并存）
"""
import aiosqlite
import json
import time
from pathlib import Path
from typing import Optional, Any

DB_PATH = Path(__file__).parent.parent / "data" / "vulnhunter.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_url TEXT NOT NULL,
    repo_name TEXT,
    status TEXT NOT NULL DEFAULT 'queued',   -- queued | cloning | analyzing | done | failed
    stage TEXT,                              -- 当前流水线阶段
    progress REAL DEFAULT 0,                 -- 0~100
    queued_at INTEGER,
    started_at INTEGER,
    finished_at INTEGER,
    error TEXT,
    llm_config_id INTEGER,                   -- 该项目使用的 LLM 配置
    review_config_id INTEGER,                -- 交叉验证使用的 LLM 配置（可与主一致）
    files_scanned INTEGER DEFAULT 0,
    files_total INTEGER DEFAULT 0,
    raw_findings INTEGER DEFAULT 0,          -- 初次扫描发现数
    confirmed_findings INTEGER DEFAULT 0,    -- 验证通过数
    rejected_findings INTEGER DEFAULT 0      -- 验证淘汰数（防幻觉成功）
);

CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    level TEXT NOT NULL,                     -- info | warn | error | stage
    stage TEXT,
    message TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    vuln_type TEXT NOT NULL,                 -- path_traversal | sqli | rce | ssrf | authz | ...
    severity TEXT NOT NULL,                  -- critical | high | medium | low
    file_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    code_snippet TEXT,
    title TEXT NOT NULL,
    summary TEXT,                            -- 简要说明
    discovery_reasoning TEXT,                -- 初次发现时模型的推理
    verification_reasoning TEXT,             -- 自验证模型的推理
    cross_review_reasoning TEXT,             -- 交叉验证模型的推理
    confidence REAL,                         -- 0~1
    data_flow TEXT,                          -- source -> sink 路径（JSON）
    fix_suggestion TEXT,                     -- 修复建议（含代码）
    full_report_md TEXT,                     -- 可直接提交的完整 Markdown
    status TEXT DEFAULT 'confirmed',         -- confirmed | rejected
    rejected_reason TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    config_id INTEGER NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    project_id INTEGER,
    stage TEXT,
    prompt_tokens INTEGER DEFAULT 0,
    completion_tokens INTEGER DEFAULT 0,
    latency_ms INTEGER DEFAULT 0,
    success INTEGER DEFAULT 1,
    error TEXT
);

CREATE TABLE IF NOT EXISTS llm_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,                  -- ollama | gemini | openai_compatible
    base_url TEXT,
    api_key TEXT,
    model TEXT NOT NULL,
    temperature REAL DEFAULT 0.2,
    max_tokens INTEGER DEFAULT 4096,
    extra_json TEXT,                         -- 任意扩展字段
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_logs_project ON scan_logs(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_ts ON api_usage(ts);
CREATE INDEX IF NOT EXISTS idx_api_usage_config ON api_usage(config_id);
"""


async def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(SCHEMA)
        await db.commit()


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


# ---------- projects ----------

async def create_project(repo_url: str, llm_config_id: int, review_config_id: int) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """INSERT INTO projects (repo_url, repo_name, status, queued_at, llm_config_id, review_config_id)
               VALUES (?, ?, 'queued', ?, ?, ?)""",
            (repo_url, repo_url.rstrip("/").split("/")[-1], int(time.time()),
             llm_config_id, review_config_id),
        )
        await db.commit()
        return cur.lastrowid


async def list_projects(limit: int = 100) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM projects ORDER BY id DESC LIMIT ?", (limit,)
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def get_project(project_id: int) -> Optional[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM projects WHERE id = ?", (project_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def update_project(project_id: int, **kwargs):
    if not kwargs:
        return
    fields = ", ".join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [project_id]
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(f"UPDATE projects SET {fields} WHERE id = ?", values)
        await db.commit()


async def get_next_queued() -> Optional[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM projects WHERE status = 'queued' ORDER BY id ASC LIMIT 1"
        )
        row = await cur.fetchone()
        return dict(row) if row else None


async def delete_project(project_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM projects WHERE id = ?", (project_id,))
        await db.commit()


async def mark_stale_projects_failed() -> int:
    """启动时把上次崩溃残留的 cloning/analyzing 项目标记为 failed。"""
    import time as _t
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "UPDATE projects SET status='failed', error='interrupted by server restart', "
            "finished_at=? WHERE status IN ('cloning', 'analyzing')",
            (int(_t.time()),),
        )
        await db.commit()
        return cur.rowcount


async def requeue_project(project_id: int) -> bool:
    """重置项目状态以便重新跑流水线。保留 url 和 llm 配置，清空进度和发现。"""
    async with aiosqlite.connect(DB_PATH) as db:
        # 删掉旧的发现和日志
        await db.execute("DELETE FROM findings WHERE project_id = ?", (project_id,))
        await db.execute("DELETE FROM scan_logs WHERE project_id = ?", (project_id,))
        cur = await db.execute(
            "UPDATE projects SET status='queued', stage='queued', progress=0.0, "
            "started_at=NULL, finished_at=NULL, error=NULL, "
            "files_scanned=0, files_total=0, raw_findings=0, "
            "confirmed_findings=0, rejected_findings=0 "
            "WHERE id = ?",
            (project_id,),
        )
        await db.commit()
        return cur.rowcount > 0


# ---------- logs ----------

async def add_log(project_id: int, level: str, stage: str, message: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO scan_logs (project_id, ts, level, stage, message) VALUES (?, ?, ?, ?, ?)",
            (project_id, int(time.time()), level, stage, message),
        )
        await db.commit()


async def get_logs(project_id: int, limit: int = 500) -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM scan_logs WHERE project_id = ? ORDER BY id ASC LIMIT ?",
            (project_id, limit),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


# ---------- findings ----------

async def add_finding(project_id: int, finding: dict) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """INSERT INTO findings
               (project_id, vuln_type, severity, file_path, line_start, line_end,
                code_snippet, title, summary, discovery_reasoning, verification_reasoning,
                cross_review_reasoning, confidence, data_flow, fix_suggestion,
                full_report_md, status, rejected_reason, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                project_id,
                finding.get("vuln_type", "unknown"),
                finding.get("severity", "medium"),
                finding.get("file_path", ""),
                finding.get("line_start"),
                finding.get("line_end"),
                finding.get("code_snippet"),
                finding.get("title", ""),
                finding.get("summary"),
                finding.get("discovery_reasoning"),
                finding.get("verification_reasoning"),
                finding.get("cross_review_reasoning"),
                finding.get("confidence", 0.0),
                json.dumps(finding.get("data_flow")) if finding.get("data_flow") else None,
                finding.get("fix_suggestion"),
                finding.get("full_report_md"),
                finding.get("status", "confirmed"),
                finding.get("rejected_reason"),
                int(time.time()),
            ),
        )
        await db.commit()
        return cur.lastrowid


async def list_findings(project_id: int, status: str = "confirmed") -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            "SELECT * FROM findings WHERE project_id = ? AND status = ? ORDER BY severity, id",
            (project_id, status),
        )
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def get_finding(finding_id: int) -> Optional[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


# ---------- api usage ----------

async def record_api_usage(config_id: int, provider: str, model: str,
                            project_id: Optional[int], stage: Optional[str],
                            prompt_tokens: int, completion_tokens: int,
                            latency_ms: int, success: bool, error: Optional[str] = None):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT INTO api_usage
               (ts, config_id, provider, model, project_id, stage,
                prompt_tokens, completion_tokens, latency_ms, success, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (int(time.time()), config_id, provider, model, project_id, stage,
             prompt_tokens, completion_tokens, latency_ms,
             1 if success else 0, error),
        )
        await db.commit()


async def get_usage_summary(hours: int = 24) -> dict:
    since = int(time.time()) - hours * 3600
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(
            """SELECT config_id, provider, model,
                      COUNT(*) AS calls,
                      SUM(prompt_tokens) AS prompt_tokens,
                      SUM(completion_tokens) AS completion_tokens,
                      SUM(latency_ms) AS total_latency_ms,
                      SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS errors
               FROM api_usage
               WHERE ts >= ?
               GROUP BY config_id, provider, model""",
            (since,),
        )
        per_model = [dict(r) for r in await cur.fetchall()]

        cur = await db.execute(
            """SELECT COUNT(*) AS total_calls,
                      SUM(prompt_tokens) AS total_prompt,
                      SUM(completion_tokens) AS total_completion,
                      SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) AS total_errors
               FROM api_usage WHERE ts >= ?""",
            (since,),
        )
        totals = dict(await cur.fetchone())

        # 时间序列（按小时）
        cur = await db.execute(
            """SELECT (ts / 3600) * 3600 AS hour_ts,
                      COUNT(*) AS calls,
                      SUM(prompt_tokens + completion_tokens) AS tokens
               FROM api_usage WHERE ts >= ?
               GROUP BY hour_ts ORDER BY hour_ts ASC""",
            (since,),
        )
        timeseries = [dict(r) for r in await cur.fetchall()]
    return {"per_model": per_model, "totals": totals, "timeseries": timeseries}


# ---------- llm configs ----------

async def create_llm_config(cfg: dict) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """INSERT INTO llm_configs
               (name, provider, base_url, api_key, model, temperature, max_tokens, extra_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cfg["name"], cfg["provider"], cfg.get("base_url"), cfg.get("api_key"),
                cfg["model"], cfg.get("temperature", 0.2), cfg.get("max_tokens", 4096),
                json.dumps(cfg.get("extra", {})), int(time.time()),
            ),
        )
        await db.commit()
        return cur.lastrowid


async def list_llm_configs() -> list[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM llm_configs ORDER BY id ASC")
        rows = await cur.fetchall()
        result = []
        for r in rows:
            d = dict(r)
            # 不回传完整 api_key
            if d.get("api_key"):
                d["api_key_masked"] = d["api_key"][:6] + "***" + d["api_key"][-4:] if len(d["api_key"]) > 12 else "***"
                d.pop("api_key")
            result.append(d)
        return result


async def get_llm_config(config_id: int) -> Optional[dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM llm_configs WHERE id = ?", (config_id,))
        row = await cur.fetchone()
        return dict(row) if row else None


async def delete_llm_config(config_id: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM llm_configs WHERE id = ?", (config_id,))
        await db.commit()
