"""The optional JEV content screener: parsing, fail-safe behaviour, and the
recall-first fold into the verdict."""

import asyncio
import json
from dataclasses import replace
from pathlib import Path

from persianphish_detector.config import DetectorConfig
from persianphish_detector.jev import (
    JevClient,
    JevFinding,
    _first_json_object,
    apply_jev,
    jev_structure,
)
from persianphish_detector.types import Verdict


class _Resp:
    def __init__(self, status: int, content: str) -> None:
        self.status_code = status
        self._content = content
        self.content = content.encode()

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


class _FakeHTTP:
    """A stub OpenAI-compatible client that returns one canned completion."""

    def __init__(self, status: int = 200, content: str = "", raises: bool = False) -> None:
        self._status = status
        self._content = content
        self._raises = raises
        self.calls: list = []

    async def post(self, path, json=None):
        self.calls.append((path, json))
        if self._raises:
            raise RuntimeError("boom")
        return _Resp(self._status, self._content)

    async def aclose(self):
        pass


def _client(http: _FakeHTTP, **kw) -> JevClient:
    return JevClient(base_url="http://jev.test", model="m1", client_factory=lambda: http, **kw)


def _score(http: _FakeHTTP, **kw) -> JevFinding:
    return asyncio.run(
        _client(http, **kw).score(url="https://x.example", visible_text="hello", structure={"host": "x.example"})
    )


# ---- client: parsing + fail-safe --------------------------------------------

def test_scores_are_parsed_and_signals_are_bounded():
    http = _FakeHTTP(content='{"phishing_score": 0.91, "scam_score": 0.95, "malware_score": 0, '
                             '"brand_impersonation_score": 0.3, "confidence": 0.7, '
                             '"label": "phishing", "signals": ["credential_form", "raw page text"]}')
    finding = _score(http)
    assert finding.ok
    assert finding.phishing_score == 0.91
    assert finding.scam_score == 0.95 and finding.malware_score == 0.0
    assert finding.label == "phishing"
    assert finding.risk == 0.95
    assert finding.signals == ["credential_form"]
    # the page text went out, the structure went out; nothing else
    assert http.calls and http.calls[0][0] == "/chat/completions"


def test_prose_around_the_json_is_tolerated():
    payload = {"phishing_score": 0.4, "scam_score": 0, "malware_score": 0,
               "brand_impersonation_score": 0, "confidence": 0.7, "label": "suspicious"}
    http = _FakeHTTP(content=f"Result:\n{json.dumps(payload)}")
    finding = _score(http)
    assert finding.ok and finding.phishing_score == 0.4 and finding.label == "suspicious"


def test_incomplete_or_invalid_scores_are_unavailable():
    for score in (None, "0", False, float("nan"), float("inf"), -0.01, 1.01):
        payload = {"scam_score": 0, "malware_score": 0, "brand_impersonation_score": 0,
                   "confidence": 0.9, "label": "legitimate"}
        if score is not None:
            payload["phishing_score"] = score
        finding = _score(_FakeHTTP(content=json.dumps(payload)))
        assert not finding.ok and finding.error == "invalid_response_schema"


def test_non_200_is_a_no_signal_finding():
    finding = _score(_FakeHTTP(status=500, content="nope"))
    assert finding.ok is False and finding.risk == 0.0 and finding.error.startswith("http_")


def test_provider_deadline_cancels_stalled_request():
    class StalledHTTP:
        cancelled = False

        async def post(self, *args, **kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled = True

    http = StalledHTTP()
    finding = _score(http, timeout_s=0.01)
    assert http.cancelled
    assert finding.error == "client_timeouterror"
    assert finding.audit_summary()["risk"] is None


def test_an_exception_is_swallowed_into_no_signal():
    finding = _score(_FakeHTTP(raises=True))
    assert finding.ok is False and finding.risk == 0.0 and finding.error.startswith("client_")


def test_unparseable_content_is_no_signal():
    finding = _score(_FakeHTTP(content="I cannot help with that."))
    assert finding.ok is False and finding.error == "unparseable_response"


def test_first_json_object_extracts_the_first_balanced_object():
    assert _first_json_object('x {"a": {"b": 1}} y {"c": 2}') == {"a": {"b": 1}}
    assert _first_json_object("no object here") is None


# ---- structure summary: bounded, present-keys only --------------------------

def test_structure_is_host_plus_only_present_keys():
    summary = jev_structure(
        {"password_input_count": 1.0, "path_depth": 3.0, "not_a_known_key": 9.0},
        "https://login.bank.example/x",
    )
    assert summary["host"] == "login.bank.example"
    assert summary["password_input_count"] == 1 and summary["path_depth"] == 3
    assert "not_a_known_key" not in summary   # only the curated, security-relevant keys


# ---- fold into the verdict: recall-first, safe by default -------------------

def _cfg(tmp=Path("/tmp"), **kw) -> DetectorConfig:
    base = DetectorConfig(
        artifact_path=tmp / "m.joblib", intel_db_path=tmp / "i.db",
        review_db_path=tmp / "r.db", result_dir=tmp / "out",
    )
    return replace(base, **kw) if kw else base


def _finding(**kw) -> JevFinding:
    return JevFinding(ok=True, **kw)


def test_high_risk_escalates_a_would_be_legitimate_page():
    verdict, reasons = apply_jev(
        Verdict.LEGITIMATE, _finding(phishing_score=0.8, label="phishing"), False, _cfg()
    )
    assert verdict == Verdict.SUSPICIOUS
    assert "jev_escalated_to_review" in reasons and "jev_risk:0.80" in reasons


def test_low_risk_leaves_the_verdict_untouched():
    verdict, reasons = apply_jev(
        Verdict.LEGITIMATE,
        _finding(phishing_score=0.1, label="legitimate", confidence=0.9),
        False, _cfg(),
    )
    assert verdict == Verdict.LEGITIMATE and "jev_escalated_to_review" not in reasons


def test_jev_phishing_finding_goes_to_reviewer():
    hot = _finding(phishing_score=0.95, label="phishing")
    assert apply_jev(Verdict.LEGITIMATE, hot, False, _cfg())[0] == Verdict.SUSPICIOUS


def test_legit_short_circuit_is_opt_in_and_refused_over_deterministic_risk():
    calm = _finding(phishing_score=0.01, label="legitimate", confidence=0.9)
    cfg = _cfg(jev_short_circuit_legit=True, jev_base_url="http://model.example/v1", jev_model="mock")
    assert apply_jev(Verdict.SUSPICIOUS, calm, False, cfg, standalone=True)[0] == Verdict.LEGITIMATE
    # a deterministic risk signal blocks the clear
    assert apply_jev(Verdict.SUSPICIOUS, calm, True, cfg, standalone=True)[0] == Verdict.SUSPICIOUS
    # and without the opt-in it never clears
    assert apply_jev(Verdict.SUSPICIOUS, calm, False, _cfg(), standalone=True)[0] == Verdict.SUSPICIOUS
    # Disagreement with a fast-stage verdict still goes to the reviewer.
    assert apply_jev(Verdict.SUSPICIOUS, calm, False, cfg)[0] == Verdict.SUSPICIOUS


def test_an_unavailable_finding_defers_a_fast_clear():
    verdict, reasons = apply_jev(
        Verdict.LEGITIMATE, JevFinding(ok=False, error="client_timeout"), False, _cfg()
    )
    assert verdict == Verdict.SUSPICIOUS and reasons == ["jev_unavailable:client_timeout"]
