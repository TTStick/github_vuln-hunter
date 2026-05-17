"""
FastAPI 主入口
"""
import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import analyzer
import database
import llm_providers


FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


# ---------------- 队列 worker ----------------

queue_event = asyncio.Event()


async def queue_worker():
    """常驻协程，挑队列里下一个 queued 项目跑流水线。"""
    while True:
        try:
            nxt = await database.get_next_queued()
            if nxt is None:
                # 等新任务
                try:
                    await asyncio.wait_for(queue_event.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    pass
                queue_event.clear()
                continue
            try:
                await analyzer.run_pipeline_for_project(nxt["id"])
            except Exception as e:
                print(f"[worker] project {nxt['id']} failed: {e!r}")
        except Exception as e:
            print(f"[worker] loop error: {e!r}")
            await asyncio.sleep(2)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await database.init_db()
    # 启动清理：把上次崩溃残留的 cloning/analyzing 任务标记为 failed
    stale = await database.mark_stale_projects_failed()
    if stale:
        print(f"[startup] marked {stale} interrupted project(s) as failed")
    # 清理 data/repos 残留目录
    import shutil
    repos_dir = Path(__file__).parent.parent / "data" / "repos"
    if repos_dir.exists():
        cleaned = 0
        for sub in repos_dir.iterdir():
            if sub.is_dir():
                shutil.rmtree(sub, ignore_errors=True)
                cleaned += 1
        if cleaned:
            print(f"[startup] cleaned {cleaned} leftover repo dir(s) under data/repos/")
    task = asyncio.create_task(queue_worker())
    yield
    task.cancel()


app = FastAPI(title="Vuln Hunter", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)


# ---------------- Pydantic 模型 ----------------

class LLMConfigIn(BaseModel):
    name: str
    provider: str = Field(..., pattern="^(ollama|gemini|openai_compatible)$")
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: str
    temperature: float = 0.2
    max_tokens: int = 4096


class ProjectIn(BaseModel):
    repo_url: str
    llm_config_id: int
    review_config_id: Optional[int] = None  # 不填则与主一致


class TestLLMIn(BaseModel):
    provider: str
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: str


# ---------------- LLM 配置 ----------------

@app.get("/api/llm-configs")
async def llm_configs_list():
    return await database.list_llm_configs()


@app.post("/api/llm-configs")
async def llm_configs_create(cfg: LLMConfigIn):
    cfg_id = await database.create_llm_config(cfg.model_dump())
    return {"id": cfg_id}


@app.delete("/api/llm-configs/{cfg_id}")
async def llm_configs_delete(cfg_id: int):
    await database.delete_llm_config(cfg_id)
    return {"ok": True}


@app.post("/api/llm-configs/test")
async def llm_configs_test(body: TestLLMIn):
    """测试一个尚未保存的 LLM 配置能否通。"""
    tmp = {
        "id": 0, "provider": body.provider, "model": body.model,
        "base_url": body.base_url, "api_key": body.api_key,
        "temperature": 0.0, "max_tokens": 64,
    }
    client = llm_providers.LLMClient(tmp)
    try:
        text = await client.chat(
            [{"role": "user", "content": "Reply with exactly: PONG"}],
            stage="health_check", max_retries=0,
        )
        return {"ok": True, "reply": text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e)[:400]}


@app.get("/api/llm-configs/discover-ollama")
async def discover_ollama(base_url: str = "http://localhost:11434"):
    """傻瓜式：列出本地 Ollama 已拉的模型。"""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"{base_url.rstrip('/')}/api/tags")
            r.raise_for_status()
            data = r.json()
        models = [m.get("name") for m in data.get("models", []) if m.get("name")]
        return {"ok": True, "models": models}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/llm-configs/discover-gemini")
async def discover_gemini(api_key: str,
                           base_url: str = "https://generativelanguage.googleapis.com"):
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"{base_url.rstrip('/')}/v1beta/models?key={api_key}"
            )
            r.raise_for_status()
            data = r.json()
        models = []
        for m in data.get("models", []):
            name = m.get("name", "")
            if name.startswith("models/"):
                name = name[len("models/"):]
            methods = m.get("supportedGenerationMethods", [])
            if "generateContent" in methods:
                models.append(name)
        return {"ok": True, "models": models}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/api/llm-configs/discover-openai")
async def discover_openai(base_url: str, api_key: Optional[str] = None):
    """探测 OpenAI 兼容端点的 /v1/models。"""
    try:
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{base_url.rstrip('/')}/v1/models", headers=headers)
            r.raise_for_status()
            data = r.json()
        models = [m.get("id") for m in data.get("data", []) if m.get("id")]
        return {"ok": True, "models": models}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------------- 项目 ----------------

@app.get("/api/projects")
async def projects_list():
    return await database.list_projects()


@app.post("/api/projects")
async def projects_create(p: ProjectIn):
    review_id = p.review_config_id or p.llm_config_id
    pid = await database.create_project(p.repo_url, p.llm_config_id, review_id)
    queue_event.set()
    return {"id": pid}


@app.get("/api/projects/{pid}")
async def projects_get(pid: int):
    proj = await database.get_project(pid)
    if not proj:
        raise HTTPException(404)
    return proj


@app.delete("/api/projects/{pid}")
async def projects_delete(pid: int):
    await database.delete_project(pid)
    return {"ok": True}


@app.post("/api/projects/{pid}/requeue")
async def projects_requeue(pid: int):
    proj = await database.get_project(pid)
    if not proj:
        raise HTTPException(404)
    if proj["status"] in ("queued", "cloning", "analyzing"):
        raise HTTPException(400, "project is already queued or running")
    ok = await database.requeue_project(pid)
    if not ok:
        raise HTTPException(500, "failed to requeue")
    queue_event.set()
    return {"ok": True}


@app.get("/api/projects/{pid}/logs")
async def projects_logs(pid: int):
    return await database.get_logs(pid)


@app.get("/api/projects/{pid}/findings")
async def projects_findings(pid: int, status: str = "confirmed"):
    return await database.list_findings(pid, status)


@app.get("/api/findings/{fid}")
async def findings_get(fid: int):
    f = await database.get_finding(fid)
    if not f:
        raise HTTPException(404)
    return f


@app.get("/api/findings/{fid}/report")
async def findings_report(fid: int):
    f = await database.get_finding(fid)
    if not f:
        raise HTTPException(404)
    md = f.get("full_report_md") or "(no report)"
    return JSONResponse(
        content={"markdown": md, "title": f.get("title", "report")},
        headers={"X-Filename": f"finding_{fid}.md"},
    )


# ---------------- 仪表盘 ----------------

@app.get("/api/dashboard")
async def dashboard(hours: int = 24):
    projects = await database.list_projects(limit=200)
    by_status: dict[str, int] = {}
    for p in projects:
        by_status[p["status"]] = by_status.get(p["status"], 0) + 1
    usage = await database.get_usage_summary(hours=hours)
    return {
        "projects_by_status": by_status,
        "projects_total": len(projects),
        "active": [p for p in projects if p["status"] in ("queued", "cloning", "analyzing")],
        "usage": usage,
    }


# ---------------- WebSocket 实时推送 ----------------

@app.websocket("/ws/project/{pid}")
async def ws_project(websocket: WebSocket, pid: int):
    await websocket.accept()
    last_log_id = 0
    try:
        while True:
            proj = await database.get_project(pid)
            if proj:
                logs = await database.get_logs(pid, limit=500)
                new_logs = [l for l in logs if l["id"] > last_log_id]
                if new_logs:
                    last_log_id = new_logs[-1]["id"]
                await websocket.send_json({
                    "project": proj,
                    "new_logs": new_logs,
                })
                if proj["status"] in ("done", "failed"):
                    # 推送完整 findings
                    findings = await database.list_findings(pid)
                    await websocket.send_json({"final_findings": findings})
                    break
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"error": str(e)})
        except Exception:
            pass


# ---------------- 静态前端 ----------------

@app.get("/")
async def index():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app", host="0.0.0.0", port=8765, reload=False,
    )
