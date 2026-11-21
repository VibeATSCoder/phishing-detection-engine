import asyncio
import json

import httpx
import pytest

from persianphish_detector.jev import JevClient


def provider_answers():
    return [
        {"type": "choice", "name": "label", "choice": "suspicious", "confidence": 0.83},
        {"type": "predicate", "name": "malware_score", "probability": 0.04},
        {"type": "predicate", "name": "brand_impersonation_score", "probability": 0.93},
        {"type": "predicate", "name": "scam_score", "probability": 0.15},
        {"type": "predicate", "name": "phishing_score", "probability": 0.80},
    ]


def score(body):
    def endpoint(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/decisions"
        assert request.headers["authorization"] == "Bearer fixture-key"
        payload = json.loads(request.content)
        assert payload["model"] == "jev-latest" and "messages" not in payload
        assert "private-url-parameter" not in payload["input"]
        assert json.loads(payload["input"])["visible_text"] == "ordinary page"
        choice = next(q for q in payload["questions"] if q["name"] == "label")
        assert choice["type"] == "choice" and len(choice["choices"]) == 3
        return httpx.Response(200, json=body)

    async def run():
        jev = JevClient(
            base_url="https://provider.example/v1", model="jev-latest", api_format="decisions",
            client_factory=lambda: httpx.AsyncClient(
                base_url="https://provider.example/v1",
                headers={"authorization": "Bearer fixture-key"},
                transport=httpx.MockTransport(endpoint),
            ),
        )
        try:
            return await jev.score(
                url="https://site.example/?private-url-parameter=1",
                visible_text="ordinary page", structure={"form_count": 0},
            )
        finally:
            await jev.close()

    return asyncio.run(run())


def test_decisions_maps_reordered_named_answers_and_provider_confidence():
    finding = score({"model": "jev-latest", "answers": provider_answers()})
    assert finding.ok and finding.label == "suspicious"
    assert finding.risk == 0.93 and finding.phishing_score == 0.80
    assert finding.confidence == 0.83


@pytest.mark.parametrize("issue", ["missing", "duplicate", "refusal", "invalid_probability"])
def test_decisions_invalid_answers_have_no_risk_score(issue):
    answers = provider_answers()
    if issue == "missing":
        answers.pop()
    elif issue == "duplicate":
        answers.append(answers[-1])
    elif issue == "refusal":
        answers[-1]["type"] = "refusal"
    else:
        answers[-1]["probability"] = True
    finding = score({"answers": answers})
    assert not finding.ok and finding.error == "invalid_response_schema"
    assert finding.audit_summary()["risk"] is None
