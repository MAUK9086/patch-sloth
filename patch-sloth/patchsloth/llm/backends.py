"""LLM backends for the Task A second opinion. All share predict_vectors(rows) -> list[str] (SPEC §11.7).
Select with PATCHSLOTH_LLM_BACKEND = null | vllm | tinker."""
from typing import Protocol

from .. import config


class LLMBackend(Protocol):
    name: str

    def predict_vectors(self, rows) -> list[str]:
        """rows: objects/Series with cna, cna_cwe, cna_vector, description. Returns CVSS v3.1 vectors."""
        ...


class NullBackend:
    """Returns the CNA vector unchanged (used with --no-llm and in tests)."""
    name = "null"

    def predict_vectors(self, rows) -> list[str]:
        return [r.cna_vector for r in rows]


class VLLMBackend:
    """OpenAI-compatible /v1/chat/completions on the GPU Droplet (deploy/vllm-droplet.sh), model="patchsloth".
    Same prompt as training: Qwen3's chat template with enable_thinking=False renders the same tokens as Tinker's
    qwen3_disable_thinking renderer (checked on 200 test rows, DECISIONS.md). Greedy, max_tokens 48; parse failures
    fall back to the CNA vector, as in scripts/06. scripts/12_vllm_parity.py compares the outputs with Tinker's."""
    name = "vllm"

    def __init__(self, base_url: str | None = None, api_key: str | None = None, client=None,
                 max_tokens: int = 48, concurrency: int = 8, timeout: float = 30):
        base_url = base_url or config.VLLM_BASE_URL
        api_key = api_key or config.VLLM_API_KEY
        if not base_url and client is None:
            raise RuntimeError("VLLM_BASE_URL is not set")
        if client is None:
            from openai import OpenAI
            client = OpenAI(base_url=base_url, api_key=api_key or "none", timeout=timeout, max_retries=1)
        self.client, self.max_tokens, self.concurrency = client, max_tokens, concurrency

    def complete(self, row) -> str:
        from .prompt import messages
        r = self.client.chat.completions.create(
            model=config.VLLM_MODEL, messages=messages(row), temperature=0, max_tokens=self.max_tokens,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}})
        return r.choices[0].message.content or ""

    def predict_vectors(self, rows) -> list[str]:
        from concurrent.futures import ThreadPoolExecutor

        from .prompt import parse_output
        rows = list(rows)
        with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
            texts = list(ex.map(self.complete, rows))
        return [parse_output(t, r.cna_vector)[0] for t, r in zip(texts, rows)]


class TinkerBackend:
    """Tinker sampling client with the saved fine-tuned weights. Filled in at M3."""
    name = "tinker"

    def predict_vectors(self, rows) -> list[str]:
        raise NotImplementedError("TinkerBackend is implemented after the Tinker run (M3)")


class PrecomputedBackend:
    """Fine-tuned vectors computed in bulk (scripts/16, Tinker) for the feed build. Returns None for CVEs it has no
    vector for, so callers can tell "no LLM opinion" apart from "the LLM agreed with the CNA"."""
    name = "tinker-precomputed"

    def __init__(self, path=None):
        import json
        from pathlib import Path
        self.vectors = json.loads(Path(path or config.RESULTS / "llm_vectors_ft_unanalysed.json").read_text())

    def predict_vectors(self, rows) -> list[str | None]:
        return [self.vectors.get(r.cve) for r in rows]


def get_backend(name: str | None = None) -> LLMBackend:
    name = (name or config.LLM_BACKEND or "null").lower()
    return {"null": NullBackend, "vllm": VLLMBackend, "tinker": TinkerBackend,
            "precomputed": PrecomputedBackend}[name]()
