"""Guardrail (SPEC §11.4): injected CVE IDs or numbers are caught; retry once; then template fallback."""
import json
from types import SimpleNamespace

from patchsloth import report
from patchsloth.priority import prioritise_all

MED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


def payload():
    rows = prioritise_all([
        dict(cve="CVE-2026-1111", package="lodash", version="4.17.20", fixed="4.17.21", cna_vector=MED,
             predicted_vector=HIGH, p_bump=0.8213, epss=0.0123, kev_date=None, source="model"),
        dict(cve="CVE-2025-2222", package="jinja2", version="2.10", fixed=None, cna_vector=MED,
             predicted_vector=MED, p_bump=0.01, epss=None, kev_date=None, source="model"),
    ], tau=0.3, tau_high=0.7)
    return report.build_payload(rows, data_as_of="2026-10-21T14:41Z", epss_date="2026-10-21")


def facts():
    return json.dumps(payload())


def test_template_passes_guardrail():
    md = report.template_report(payload())
    ok, bad = report.guardrail(md, facts())
    assert ok, bad
    assert "CVE-2026-1111" in md and "estimates for triage" in md


def test_faithful_text_passes():
    text = ("Update lodash 4.17.20 to 4.17.21: CVE-2026-1111 is likely under-rated (p=0.82), "
            "CNA MEDIUM 5.4 vs predicted HIGH 7.5. Data as of 2026-10-21. 1. P0 table follows.")
    assert report.guardrail(text, facts()) == (True, [])


def test_nist_reviewed_row_shows_both_severities_and_no_prediction():
    row = dict(cve="CVE-2026-3333", package="lodash", version="4.17.20", fixed="4.18.0",
               cna_vector=MED, predicted_vector=HIGH, p_bump=0.9, source="nvd")
    rows = prioritise_all([row], tau=0.3, tau_high=0.7)
    pl = report.build_payload(rows)
    r = pl["rows"][0]
    assert r["nist_reviewed"] and r["p_bump"] is None and r["predicted_vector"] is None
    assert r["nvd_severity"] == "HIGH" and r["cna_severity"] == "MEDIUM"
    md = report.template_report(pl)
    assert "NIST-reviewed: CNA MEDIUM / NVD HIGH" in md and "p(higher)" not in md


def test_fake_cve_is_caught():
    ok, bad = report.guardrail("Also patch CVE-2024-99999 right away.", facts())
    assert not ok and "CVE-2024-99999" in bad


def test_fake_number_is_caught():
    ok, bad = report.guardrail("CVE-2026-1111 scores 9.8 and is exploited by 37% of attackers.", facts())
    assert not ok and "9.8" in bad and "37" in bad


def test_fake_version_is_caught():
    ok, bad = report.guardrail("Upgrade lodash to 4.18.0.", facts())
    assert not ok and "4.18.0" in bad


def test_cve_digits_do_not_whitelist_numbers():
    ok, bad = report.guardrail("Score 1111.", facts())
    assert not ok and "1111" in bad


class FakeClient:
    """Mimics openai.OpenAI().chat.completions.create with canned answers."""

    def __init__(self, answers):
        self.answers, self.calls = list(answers), 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.calls += 1
        assert kw["model"] == "ultramarine-1-flash" and kw["reasoning_effort"] == "low"
        msg = SimpleNamespace(content=self.answers.pop(0), tool_calls=None)
        usage = SimpleNamespace(prompt_tokens=1000, completion_tokens=200,
                                prompt_tokens_details=SimpleNamespace(cached_tokens=0))
        return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason="stop")], usage=usage)


def test_retry_then_template_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(report.costs, "COSTS_FILE", tmp_path / "costs.jsonl")
    client = FakeClient(["Patch CVE-2099-0001 now.", "It scores 9.9."])
    out = report.write_report(payload(), use_llm=True, client=client)
    assert client.calls == 2 and out["writer"] == "template-fallback" and out["guardrail_ok"] is False
    assert "CVE-2026-1111" in out["report_md"]
    logged = [json.loads(line) for line in open(tmp_path / "costs.jsonl")]
    assert [r["guardrail_ok"] for r in logged] == [False, False] and logged[0]["usd"] > 0


def test_retry_succeeds(tmp_path, monkeypatch):
    monkeypatch.setattr(report.costs, "COSTS_FILE", tmp_path / "costs.jsonl")
    client = FakeClient(["Patch CVE-2099-0001 now.", "Patch CVE-2026-1111 (lodash 4.17.21)."])
    out = report.write_report(payload(), use_llm=True, client=client)
    assert out["writer"] == "ultramarine" and out["attempts"] == 2


def test_no_key_uses_template(monkeypatch):
    monkeypatch.setattr(report.config, "PAPERINSTRUMENTS_API_KEY", "")
    out = report.write_report(payload())
    assert out["writer"] == "template" and out["usd"] == 0.0
