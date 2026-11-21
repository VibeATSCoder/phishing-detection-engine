"""Split isolation for offline local JEV training and comparison."""

from __future__ import annotations

import pandas as pd

from ..features import FEATURE_COLUMNS
from ..url_utils import registrable_domain


def isolated_splits(frame: pd.DataFrame) -> dict[str, pd.DataFrame]:
    trusted = frame.loc[
        frame["training_eligible"].eq(1)
        & (
            (frame["label"].eq(0) & frame["label_quality"].eq("verified_legitimate"))
            | (frame["label"].eq(1) & frame["label_quality"].eq("generated_phishing"))
        )
    ]
    if trusted["group_id"].isna().any() or (trusted.groupby("group_id")["split"].nunique() > 1).any():
        raise ValueError("eligible groups must be separated across splits")

    seen_domains: set[str] = set()
    seen_vectors: set[tuple] = set()
    isolated = {}
    for name in ("train", "calibration", "policy", "test"):
        split = trusted.loc[trusted["split"].eq(name)]
        domains = [registrable_domain(url) for url in split["url"]]
        vectors = list(split[FEATURE_COLUMNS].itertuples(index=False, name=None))
        keep = [
            domain not in seen_domains and vector not in seen_vectors
            for domain, vector in zip(domains, vectors)
        ]
        isolated[name] = split.loc[keep]
        # Earlier splits keep priority, including cases dropped by a separate
        # criterion, since the shipped RF/TCN already used them.
        seen_domains.update(domains)
        seen_vectors.update(vectors)
    return isolated
