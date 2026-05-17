"""
LLM Provider 抽象层

支持三种后端：
  - ollama:              本地 Ollama (http://localhost:11434), /api/chat
  - gemini:              Google Gemini, generateContent
  - openai_compatible:   任何 OpenAI Chat Completions 协议的服务
                         (OpenAI / 硅基流动 / DeepSeek / Together / 用户自建)

对外暴露统一的 chat() 协程，输入 messages，输出 (text, usage)
所有 provider 都会自动记录 api_usage 表，便于仪表盘统计。
"""
import asyncio
import json
import time
from typing import Optional
import httpx

import database


class LLMError(Exception):
    pass


class LLMClient:
    def __init__(self, config: dict):
        self.config = config
        self.id: int = config["id"]
        self.provider: str = config["provider"]
        self.model: str = config["model"]
        self.base_url: Optional[str] = config.get("base_url")
        self.api_key: Optional[str] = config.get("api_key")
        self.temperature: float = config.get("temperature", 0.2)
        self.max_tokens: int = config.get("max_tokens", 4096)

    async def chat(self, messages: list[dict], project_id: Optional[int] = None,
                   stage: Optional[str] = None, json_mode: bool = False,
                   max_retries: int = 2) -> str:
        """messages 形如 [{'role':'system'|'user'|'assistant', 'content':...}]"""
        last_err = None
        for attempt in range(max_retries + 1):
            t0 = time.time()
            try:
                if self.provider == "ollama":
                    text, usage = await self._ollama_chat(messages, json_mode)
                elif self.provider == "gemini":
                    text, usage = await self._gemini_chat(messages, json_mode)
                elif self.provider == "openai_compatible":
                    text, usage = await self._openai_chat(messages, json_mode)
                else:
                    raise LLMError(f"Unknown provider: {self.provider}")

                await database.record_api_usage(
                    config_id=self.id, provider=self.provider, model=self.model,
                    project_id=project_id, stage=stage,
                    prompt_tokens=usage.get("prompt_tokens", 0),
                    completion_tokens=usage.get("completion_tokens", 0),
                    latency_ms=int((time.time() - t0) * 1000),
                    success=True,
                )
                return text
            except Exception as e:
                last_err = e
                await database.record_api_usage(
                    config_id=self.id, provider=self.provider, model=self.model,
                    project_id=project_id, stage=stage,
                    prompt_tokens=0, completion_tokens=0,
                    latency_ms=int((time.time() - t0) * 1000),
                    success=False, error=str(e)[:300],
                )
                if attempt < max_retries:
                    await asyncio.sleep(1.5 * (attempt + 1))
                else:
                    raise LLMError(f"{self.provider}/{self.model} failed after retries: {e}") from e
        raise LLMError(str(last_err))

    # ---- Ollama ----
    async def _ollama_chat(self, messages, json_mode):
        base = (self.base_url or "http://localhost:11434").rstrip("/")
        url = f"{base}/api/chat"
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        }
        if json_mode:
            payload["format"] = "json"
        async with httpx.AsyncClient(timeout=600) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
        text = data.get("message", {}).get("content", "")
        usage = {
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
        }
        return text, usage

    # ---- Gemini ----
    async def _gemini_chat(self, messages, json_mode):
        if not self.api_key:
            raise LLMError("Gemini requires api_key")
        base = (self.base_url or "https://generativelanguage.googleapis.com").rstrip("/")
        url = f"{base}/v1beta/models/{self.model}:generateContent?key={self.api_key}"

        # Gemini 把 system 拆成 systemInstruction，把 user/assistant 转 user/model
        system_text = "\n".join(m["content"] for m in messages if m["role"] == "system")
        contents = []
        for m in messages:
            if m["role"] == "system":
                continue
            role = "user" if m["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": m["content"]}]})
        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens,
            },
        }
        if system_text:
            payload["systemInstruction"] = {"parts": [{"text": system_text}]}
        if json_mode:
            payload["generationConfig"]["responseMimeType"] = "application/json"

        async with httpx.AsyncClient(timeout=600) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
        try:
            text = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError):
            raise LLMError(f"Gemini empty response: {json.dumps(data)[:300]}")
        usage_meta = data.get("usageMetadata", {})
        usage = {
            "prompt_tokens": usage_meta.get("promptTokenCount", 0),
            "completion_tokens": usage_meta.get("candidatesTokenCount", 0),
        }
        return text, usage

    # ---- OpenAI-compatible ----
    async def _openai_chat(self, messages, json_mode):
        if not self.base_url:
            raise LLMError("openai_compatible requires base_url")
        url = f"{self.base_url.rstrip('/')}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        async with httpx.AsyncClient(timeout=600) as client:
            r = await client.post(url, headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()
        text = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {}) or {}
        return text, {
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
        }


async def make_client(config_id: int) -> LLMClient:
    cfg = await database.get_llm_config(config_id)
    if not cfg:
        raise LLMError(f"LLM config {config_id} not found")
    return LLMClient(cfg)


# 工具：从 LLM 输出里提取 JSON
def extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    text = text.strip()
    # 去掉 ```json ... ``` 围栏
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        if text.endswith("```"):
            text = text[: text.rfind("```")]
    text = text.strip()
    # 寻找 { ... } 或 [ ... ]
    for opener, closer in [("{", "}"), ("[", "]")]:
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
