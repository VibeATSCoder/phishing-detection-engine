"""The forest must be scored on the origin, not the browsed URL.

Not one of the 935 legitimate rows in the training corpus carries a URL path,
while 153 of the 845 phishing rows do. The forest only ever saw a path on a
phishing example, so on identical page HTML it scores aparat.com/ at 0.074 and
aparat.com/home at 0.962. Without this, every subpage of every legitimate site
is flagged.
"""

from __future__ import annotations

from persianphish_detector.orchestrator import _rf_input_features
from persianphish_detector.types import CrawlEvidence, CrawlStatus


def _evidence(final_url: str) -> CrawlEvidence:
    return CrawlEvidence(
        target_url="https://example.ir/",
        final_url=final_url,
        status=CrawlStatus.OK,
        http_status=200,
        content_type="text/html",
        html="<html><head><title>t</title></head><body><p>hello</p></body></html>",
        screenshot=None,
        redirect_chain=["https://example.ir/"],
        response_headers={},
        network_hosts=[],
        source="http",
        quality_score=0.9,
        quality_reasons=[],
        elapsed_ms=10.0,
    )


def test_a_browsed_subpage_is_scored_as_its_origin() -> None:
    full = _rf_input_features({}, _evidence("https://example.ir/account/login"), None, False)
    origin, used = _rf_input_features({}, _evidence("https://example.ir/account/login"), None, True)
    assert used is True
    assert origin["path_length"] == 1, "the path must be gone from the scored view"
    assert origin["path_depth"] == 0
    assert full[1] is False


def test_a_bare_origin_is_left_alone() -> None:
    _, used = _rf_input_features({}, _evidence("https://example.ir/"), None, True)
    assert used is False, "nothing to rewrite when the URL is already an origin"


def test_the_full_url_features_are_still_what_the_caller_holds() -> None:
    """Path risk must not be discarded, only kept away from the forest.

    _deterministic_risk, the token counts and the TCN all read the full-URL
    features, so a hostile path on a clean origin is still caught by signals
    that do not depend on the forest's opinion.
    """
    sentinel = {"suspicious_token_count": 4.0}
    returned, used = _rf_input_features(
        sentinel, _evidence("https://example.ir/"), None, True
    )
    assert used is False
    assert returned is sentinel
