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
    """OpenAI-compatible /v1/chat/completions on the GPU Droplet, model="patchsloth". Filled in at M6."""
    name = "vllm"

    def __init__(self, base_url: str = config.VLLM_BASE_URL, api_key: str = config.VLLM_API_KEY):
        if not base_url:
            raise RuntimeError("VLLM_BASE_URL is not set")
        self.base_url, self.api_key = base_url, api_key

    def predict_vectors(self, rows) -> list[str]:
        raise NotImplementedError("VLLMBackend is implemented with the GPU deployment (M6)")


class TinkerBackend:
    """Tinker sampling client with the saved fine-tuned weights. Filled in at M3."""
    name = "tinker"

    def predict_vectors(self, rows) -> list[str]:
        raise NotImplementedError("TinkerBackend is implemented after the Tinker run (M3)")


def get_backend(name: str | None = None) -> LLMBackend:
    name = (name or config.LLM_BACKEND or "null").lower()
    return {"null": NullBackend, "vllm": VLLMBackend, "tinker": TinkerBackend}[name]()
