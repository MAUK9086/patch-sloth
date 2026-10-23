"""VLLMBackend: request shape (model, greedy, thinking off) and parsing with the CNA fallback, using a fake client."""
from types import SimpleNamespace

import pytest

from patchsloth.llm.backends import VLLMBackend, get_backend

CNA = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"


class FakeClient:
    def __init__(self, answers):
        self.answers, self.calls = dict(answers), []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.calls.append(kw)
        text = self.answers[kw["messages"][1]["content"].split("\n")[0]]
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])


def row(cna):
    return SimpleNamespace(cve="CVE-2026-0001", cna=cna, cna_cwe="CWE-79", cna_vector=CNA, description="XSS")


def test_vllm_backend_parses_and_falls_back():
    client = FakeClient({"CNA: good": '{"AV":"N","AC":"L","PR":"N","UI":"N","S":"U","C":"H","I":"H","A":"H"}',
                         "CNA: bad": "sorry"})
    out = VLLMBackend(client=client, concurrency=2).predict_vectors([row("good"), row("bad")])
    assert out == ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CNA]
    kw = client.calls[0]
    assert kw["model"] == "patchsloth" and kw["temperature"] == 0 and kw["max_tokens"] == 48
    assert kw["extra_body"] == {"chat_template_kwargs": {"enable_thinking": False}}
    assert kw["messages"][0]["role"] == "system"


def test_vllm_backend_needs_url(monkeypatch):
    monkeypatch.setattr("patchsloth.llm.backends.config.VLLM_BASE_URL", "")
    with pytest.raises(RuntimeError):
        get_backend("vllm")
