import glob
import json
import logging
import os
import time as _time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .config import EmbeddedModelConfig, HybridLLMConfig, OllamaConfig

logger = logging.getLogger(__name__)

_GGUF_SEARCH_PATTERNS = [
    "~/.local/share/hog-security/models/hog-security*.gguf",
    "~/.hog/models/hog-security*.gguf",
    "/opt/hog/models/hog-security*.gguf",
    str(
        Path(__file__).resolve().parents[3]
        / "hog"
        / "backend"
        / "models"
        / "hog-security*.gguf"
    ),
]


@dataclass
class LLMResponse:
    content: str
    model: str
    tokens_used: int
    thinking: str = ""
    backend: str = ""


def _extract_thinking(content: str) -> tuple[str, str]:
    if "<think>" not in content:
        return content, ""
    think_start = content.index("<think>") + len("<think>")
    if "</think>" in content:
        think_end = content.index("</think>")
        thinking = content[think_start:think_end].strip()
        content = content[think_end + len("</think>") :].strip()
    else:
        thinking = content[think_start:].strip()
        content = ""
    return content, thinking


def _discover_gguf_model(explicit_path: str = "") -> str | None:
    if explicit_path and Path(explicit_path).is_file():
        return explicit_path

    env_path = os.environ.get("HOG_MODEL_PATH", "")
    if env_path and Path(env_path).is_file():
        return env_path

    for pattern in _GGUF_SEARCH_PATTERNS:
        expanded = os.path.expanduser(pattern)
        matches = sorted(glob.glob(expanded), reverse=True)
        if matches:
            return matches[0]

    cwd_matches = sorted(glob.glob("hog-security*.gguf"), reverse=True)
    if cwd_matches:
        return cwd_matches[0]

    return None


class HybridLLMClient:
    def __init__(self, config: HybridLLMConfig):
        self.config = config
        self._embedded_model = None
        self._ollama_client: httpx.Client | None = None
        self._active_backend: str = "none"
        self._model_path: str = ""

        self._init_backend()

    def _init_backend(self) -> None:
        backend = self.config.backend

        if backend in ("auto", "embedded"):
            if self._try_init_embedded():
                return
            if backend == "embedded":
                logger.warning("Embedded backend requested but failed to initialize")

        if backend in ("auto", "ollama"):
            if self._try_init_ollama():
                return
            if backend == "ollama":
                logger.warning("Ollama backend requested but failed to initialize")

        logger.warning(
            "No LLM backend available. Run 'pip install llama-cpp-python' for embedded "
            "or configure Ollama at %s",
            self.config.ollama.base_url,
        )

    def _try_init_embedded(self) -> bool:
        try:
            from llama_cpp import Llama
        except ImportError:
            logger.debug("llama-cpp-python not installed, skipping embedded backend")
            return False

        model_path = _discover_gguf_model(self.config.embedded.model_path)
        if not model_path:
            logger.debug("No GGUF model file found, skipping embedded backend")
            return False

        try:
            cfg = self.config.embedded
            self._embedded_model = Llama(
                model_path=model_path,
                n_ctx=cfg.n_ctx,
                n_threads=cfg.n_threads or None,
                n_gpu_layers=cfg.n_gpu_layers,
                verbose=cfg.verbose,
            )
            self._model_path = model_path
            self._active_backend = "embedded"
            logger.info("Embedded LLM loaded: %s", Path(model_path).name)
            return True
        except (ValueError, RuntimeError, OSError) as exc:
            logger.warning("Failed to load GGUF model %s: %s", model_path, exc)
            return False

    def _try_init_ollama(self) -> bool:
        try:
            client = httpx.Client(
                base_url=self.config.ollama.base_url,
                timeout=httpx.Timeout(self.config.ollama.timeout, connect=10.0),
            )
            resp = client.get("/api/tags", timeout=10.0)
            if resp.status_code == 200:
                self._ollama_client = client
                self._active_backend = "ollama"
                logger.info("Ollama connected at %s", self.config.ollama.base_url)
                return True
            client.close()
            return False
        except Exception:
            return False

    def generate(
        self,
        prompt: str,
        system: str = "",
        model: str | None = None,
        timeout: int | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        if self._active_backend == "embedded":
            return self._generate_embedded(prompt, system, max_tokens)
        if self._active_backend == "ollama":
            return self._generate_ollama(prompt, system, model, timeout, max_tokens)
        raise RuntimeError(
            "No LLM backend available. Install llama-cpp-python for embedded "
            f"or ensure Ollama is running at {self.config.ollama.base_url}"
        )

    def _generate_embedded(
        self,
        prompt: str,
        system: str = "",
        max_tokens: int | None = None,
    ) -> LLMResponse:
        from llama_cpp import Llama

        model: Llama = self._embedded_model  # type: ignore[assignment]
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        result: dict = model.create_chat_completion(  # type: ignore[assignment]
            messages=messages,  # type: ignore[arg-type]
            max_tokens=max_tokens or self.config.ollama.max_tokens,
            temperature=self.config.ollama.temperature,
        )

        choices = result.get("choices", [])
        raw_content = str(choices[0]["message"]["content"]) if choices else ""
        content, thinking = _extract_thinking(raw_content)
        usage = result.get("usage") or {}
        tokens = usage.get("completion_tokens", 0)

        return LLMResponse(
            content=content,
            model=Path(self._model_path).stem,
            tokens_used=tokens,
            thinking=thinking,
            backend="embedded",
        )

    def _generate_ollama(
        self,
        prompt: str,
        system: str = "",
        model: str | None = None,
        timeout: int | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        model = model or self.config.ollama.model
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        call_timeout = timeout or self.config.ollama.timeout
        call_max_tokens = max_tokens or self.config.ollama.max_tokens

        assert self._ollama_client is not None
        resp = self._ollama_client.post(
            "/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": self.config.ollama.temperature,
                    "num_predict": call_max_tokens,
                },
            },
            timeout=httpx.Timeout(call_timeout, connect=10.0),
        )
        resp.raise_for_status()
        data = resp.json()

        raw_content = data.get("message", {}).get("content", "")
        content, thinking = _extract_thinking(raw_content)

        return LLMResponse(
            content=content,
            model=model,
            tokens_used=data.get("eval_count", 0),
            thinking=thinking,
            backend="ollama",
        )

    def generate_json(
        self,
        prompt: str,
        system: str = "",
        model: str | None = None,
    ) -> dict[str, Any] | None:
        response = self.generate(prompt, system, model)
        return self._parse_json(response.content)

    def reason(self, prompt: str, system: str = "") -> LLMResponse:
        return self.generate(prompt, system, model=self.config.ollama.reasoning_model)

    def list_models(self) -> list[dict]:
        models = []
        if self._embedded_model:
            models.append(
                {
                    "name": Path(self._model_path).stem,
                    "size": Path(self._model_path).stat().st_size,
                    "backend": "embedded",
                }
            )
        if self._ollama_client:
            try:
                resp = self._ollama_client.get("/api/tags", timeout=10.0)
                resp.raise_for_status()
                for m in resp.json().get("models", []):
                    m["backend"] = "ollama"
                    models.append(m)
            except Exception:
                pass
        return models

    def benchmark(
        self,
        model: str,
        prompt: str = "Reply OK",
        max_tokens: int = 16,
        timeout: int = 60,
    ) -> dict:
        t0 = _time.time()
        try:
            resp = self.generate(
                prompt, model=model, timeout=timeout, max_tokens=max_tokens
            )
            elapsed = _time.time() - t0
            tps = resp.tokens_used / elapsed if elapsed > 0 else 0
            return {
                "model": model,
                "backend": resp.backend,
                "ok": True,
                "time": round(elapsed, 1),
                "tokens": resp.tokens_used,
                "tok_per_sec": round(tps, 1),
                "response": resp.content[:100],
            }
        except Exception as e:
            elapsed = _time.time() - t0
            return {
                "model": model,
                "ok": False,
                "time": round(elapsed, 1),
                "error": str(e)[:100],
            }

    def is_available(self) -> bool:
        return self._active_backend != "none"

    @property
    def active_backend(self) -> str:
        return self._active_backend

    def close(self) -> None:
        if self._embedded_model:
            del self._embedded_model
            self._embedded_model = None
        if self._ollama_client:
            self._ollama_client.close()
            self._ollama_client = None
        self._active_backend = "none"

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


class OllamaClient(HybridLLMClient):
    """Backward-compatible shim: accepts OllamaConfig, wraps in HybridLLMConfig."""

    def __init__(self, config: OllamaConfig):
        hybrid_config = HybridLLMConfig(
            backend="auto",
            embedded=EmbeddedModelConfig(),
            ollama=config,
        )
        super().__init__(hybrid_config)
