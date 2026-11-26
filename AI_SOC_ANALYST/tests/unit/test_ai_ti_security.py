"""Moteur IA (validation anti-hallucination, confidentialité), threat intelligence (quotas, confidentialité), sécurité."""
from __future__ import annotations

import json

import httpx
import pytest

from ai_soc_analyst.ai import engine as ai
from ai_soc_analyst.core.logging_setup import redact
from ai_soc_analyst.core.secrets import SecretStore
from ai_soc_analyst.core.security import hash_password, is_unsafe_archive_member, safe_filename, verify_password
from ai_soc_analyst.core.settings import Settings
from ai_soc_analyst.ti import engine as ti

RESULT = {"summary": "s", "verdict": "Likely", "limitations": [], "iocs": [], "mitre": [], "timeline": [],
          "findings": [{"finding_id": "F-001", "rule_id": "R-PS-001", "title": "PowerShell", "description": "d",
                        "status": "Likely", "confidence": 0.8, "evidence_ids": ["EVT-00001"], "mitre_ids": ["T1059.001"],
                        "severity": "High", "category": "Execution"}]}


class Secrets(dict):
    def get(self, k):  # noqa: ANN001, ANN201
        return super().get(k)

    def has(self, k):  # noqa: ANN001, ANN201
        return bool(self.get(k))


def test_local_engine_offline_without_key():
    out = ai.run_ai_analysis(Settings(), Secrets(), RESULT, [])
    assert out["provider"] == "local" and out["assessments"][0]["evidence_ids"] == ["EVT-00001"]
    assert all(h["label"].startswith("Hypothèse") for h in out["hypotheses"])


def test_privacy_mode_blocks_remote_provider():
    s = Settings()
    s.ai.provider = "openai"
    with pytest.raises(ai.AIError, match="Privacy"):
        ai.run_ai_analysis(s, Secrets(openai_api_key="sk-test"), RESULT, [])


def test_missing_key_reported():
    s = Settings(privacy_mode=False)
    s.ai.provider = "anthropic"
    with pytest.raises(ai.AIError, match="clé API"):
        ai.run_ai_analysis(s, Secrets(), RESULT, [])


def _openai_transport(content: dict, status: int = 200):  # noqa: ANN202
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["authorization"] == "Bearer sk-test"
        body = json.loads(req.content)
        assert "EVT-00001" in body["messages"][1]["content"]
        return httpx.Response(status, json={"choices": [{"message": {"content": json.dumps(content)}}]})
    return httpx.MockTransport(handler)


def test_ai_invented_evidence_rejected():
    s = Settings(privacy_mode=False)
    s.ai.provider = "openai"
    reply = {"executive_summary": "x", "assessments": [
        {"statement": "Exécution PowerShell", "status": "Likely", "confidence": 0.8, "evidence_ids": ["EVT-00001"], "mitre": ["T1059.001"]},
        {"statement": "Exfiltration vers 1.2.3.4", "status": "Confirmed", "confidence": 0.9, "evidence_ids": ["EVT-99999"]},
        {"statement": "Sans preuve", "status": "Confirmed", "confidence": 0.9, "evidence_ids": []},
        {"statement": "Technique inventée", "status": "Likely", "confidence": 0.5, "evidence_ids": ["F-001"], "mitre": ["T9999"]}],
        "hypotheses": [{"hypothesis": "h", "how_to_validate": "v", "evidence_ids": ["EVT-12345"]}]}
    out = ai.run_ai_analysis(s, Secrets(openai_api_key="sk-test"), RESULT, [], {"T1059.001"}, transport=_openai_transport(reply))
    kept = [a["statement"] for a in out["assessments"]]
    assert kept == ["Exécution PowerShell", "Technique inventée"]
    assert out["assessments"][1]["mitre"] == []
    assert len(out["rejected_assessments"]) == 2
    assert out["hypotheses"][0]["evidence_ids"] == []


@pytest.mark.parametrize("status,needle", [(401, "clé API invalide"), (429, "quota"), (500, "erreur du service")])
def test_ai_http_errors(status, needle):
    cfg = ai.ProviderConfig("openai", "m", "sk-test")
    t = httpx.MockTransport(lambda r: httpx.Response(status, json={}))
    with pytest.raises(ai.AIError, match=needle):
        ai.call_provider(cfg, "s", "u", t)


def test_ai_timeout():
    def boom(r):  # noqa: ANN001, ANN202
        raise httpx.ReadTimeout("t", request=r)
    with pytest.raises(ai.AIError, match="Délai"):
        ai.call_provider(ai.ProviderConfig("anthropic", "m", "k"), "s", "u", httpx.MockTransport(boom))


def test_anthropic_and_ollama_formats():
    def anth(r):  # noqa: ANN001, ANN202
        assert r.url.path == "/v1/messages" and r.headers["x-api-key"] == "k"
        return httpx.Response(200, json={"content": [{"type": "text", "text": '{"ok": true}'}]})
    assert ai.call_provider(ai.ProviderConfig("anthropic", "m", "k"), "s", "u", httpx.MockTransport(anth)) == '{"ok": true}'

    def oll(r):  # noqa: ANN001, ANN202
        assert r.url.path == "/api/chat"
        return httpx.Response(200, json={"message": {"content": "{}"}})
    assert ai.call_provider(ai.ProviderConfig("ollama", "m", None, "http://127.0.0.1:11434"), "s", "u", httpx.MockTransport(oll)) == "{}"


def test_local_ollama_allowed_in_privacy_mode():
    s = Settings()
    s.ai.provider = "ollama"
    ai.check_privacy(s, ai.provider_config(s, Secrets()))  # ne lève pas
    s.ai.ollama_url = "http://gpu.example.org:11434"
    with pytest.raises(ai.AIError):
        ai.check_privacy(s, ai.provider_config(s, Secrets()))


# ------------------------------------------------------------------ threat intelligence
@pytest.fixture()
def ti_ctx(ctx, monkeypatch):
    monkeypatch.setattr(ti, "MIN_INTERVAL", {k: 0 for k in ti.MIN_INTERVAL})
    return ctx


def test_ti_privacy_mode_sends_nothing(ti_ctx):
    calls = []
    eng = ti.TIEngine(ti_ctx, httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200)))
    res = eng.lookup("8.8.8.8")
    assert res[0].status == "skipped" and "Privacy" in res[0].summary and not calls


def test_ti_not_configured_shows_unverified(ti_ctx):
    ti_ctx.settings.privacy_mode = False
    eng = ti.TIEngine(ti_ctx)
    assert "non vérifiée" in eng.status_text()
    assert eng.lookup("8.8.8.8")[0].verdict == "Non vérifié"


def test_ti_internal_data_never_sent(ti_ctx):
    ti_ctx.settings.privacy_mode = False
    ti_ctx.settings.ti.enabled["virustotal"] = True
    ti_ctx.secrets.set("virustotal_api_key", "vt-key")
    calls = []
    eng = ti.TIEngine(ti_ctx, httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200)))
    for v in ("10.0.0.5", "fileserver.corp", "http://intranet.local/x", "C:\\Users\\bob\\a.exe"):
        assert eng.lookup(v)[0].status == "skipped", v
    assert not calls


def test_ti_virustotal_and_429(ti_ctx):
    ti_ctx.settings.privacy_mode = False
    ti_ctx.settings.ti.enabled["virustotal"] = True
    ti_ctx.secrets.set("virustotal_api_key", "vt-key")
    h = "d" * 64

    def handler(r):  # noqa: ANN001, ANN202
        assert r.headers["x-apikey"] == "vt-key"
        if r.url.path.endswith(h):
            return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 40, "undetected": 30}}}})
        return httpx.Response(429, headers={"Retry-After": "60"})
    eng = ti.TIEngine(ti_ctx, httpx.MockTransport(handler))
    r = eng.lookup(h)[0]
    assert r.verdict == "Malveillant" and "40" in r.summary
    assert eng.lookup(h)[0].from_cache is True
    r2 = eng.lookup("8.8.4.4")[0]
    assert r2.status == "rate_limited" and "60" in r2.summary
    assert len(eng.history()) >= 2


# ------------------------------------------------------------------ sécurité
def test_secret_store_encrypted(tmp_path):
    st = SecretStore(tmp_path / "s.bin", tmp_path / "k.key")
    st.set("openai_api_key", "sk-SECRET-123456")
    assert b"sk-SECRET" not in (tmp_path / "s.bin").read_bytes()
    assert SecretStore(tmp_path / "s.bin", tmp_path / "k.key").get("openai_api_key") == "sk-SECRET-123456"
    st.set("openai_api_key", None)
    assert not st.has("openai_api_key")


def test_redaction():
    out = redact("api_key=abcd1234efgh Authorization: Bearer xyz.abc sk-proj-AAAAAAAAAAAAAAAA user john.doe@corp.example")
    assert "abcd1234efgh" not in out and "xyz.abc" not in out and "sk-proj-AAAA" not in out and "john.doe@" not in out


def test_password_hashing():
    h = hash_password("correct horse battery")
    assert verify_password("correct horse battery", h) and not verify_password("wrong", h)
    assert "correct" not in h


@pytest.mark.parametrize("name", ["../x", "/etc/passwd", "C:\\Windows\\x", "a/../../b", "\\\\server\\share\\x"])
def test_unsafe_archive_members(name):
    assert is_unsafe_archive_member(name)


def test_safe_filename():
    s = safe_filename('..\\..\\con<>:"|?*.txt')
    assert "/" not in s and "\\" not in s and ".." not in s.split(".txt")[0][:2] and not any(c in s for c in '<>:"|?*')
