import json
from dataclasses import dataclass
from typing import Any

import httpx

from .config import OllamaConfig


@dataclass
class LLMResponse:
    content: str
    model: str
    tokens_used: int
    thinking: str = ""


class OllamaClient:
    def __init__(self, config: OllamaConfig):
        self.config: OllamaConfig = config
        self.client: httpx.Client = httpx.Client(
            base_url=config.base_url,
            timeout=httpx.Timeout(config.timeout, connect=10.0),
        )

    def generate(
        self,
        prompt: str,
        system: str = "",
        model: str | None = None,
    ) -> LLMResponse:
        model = model or self.config.model
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        resp = self.client.post(
            "/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens,
                },
            },
        )
        resp.raise_for_status()
        data = resp.json()

        content: str = data.get("message", {}).get("content", "")
        thinking = ""
        if "<think>" in content:
            think_start = content.index("<think>") + len("<think>")
            think_end = (
                content.index("</think>") if "</think>" in content else len(content)
            )
            thinking = content[think_start:think_end].strip()
            content = (
                content[think_end + len("</think>") :].strip()
                if "</think>" in content
                else ""
            )

        return LLMResponse(
            content=content,
            model=model,
            tokens_used=data.get("eval_count", 0),
            thinking=thinking,
        )

    def generate_json(
        self,
        prompt: str,
        system: str = "",
        model: str | None = None,
    ) -> dict[str, Any] | None:
        response = self.generate(prompt, system, model)
        return self._parse_json(response.content)

    def is_available(self) -> bool:
        try:
            resp = self.client.get("/api/tags")
            return resp.status_code == 200
        except Exception:
            return False

    def close(self) -> None:
        self.client.close()

    @staticmethod
    def _parse_json(content: str) -> dict[str, Any] | None:
        if not content:
            return None
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        for fence in ["```json", "```"]:
            if fence in content:
                start = content.index(fence) + len(fence)
                end = (
                    content.index("```", start)
                    if "```" in content[start:]
                    else len(content)
                )
                try:
                    return json.loads(content[start:end].strip())
                except (json.JSONDecodeError, ValueError):
                    pass

        first_brace = content.find("{")
        last_brace = content.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            try:
                return json.loads(content[first_brace : last_brace + 1])
            except json.JSONDecodeError:
                pass
        return None
