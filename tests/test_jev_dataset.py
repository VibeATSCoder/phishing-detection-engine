import pandas as pd

from persianphish_detector.features import FEATURE_COLUMNS
from persianphish_detector.models.jev_dataset import isolated_splits


def test_local_jev_excludes_domains_and_feature_vectors_seen_in_earlier_splits():
    rows = [
        ("train", "https://www.first-example.com/", 1),
        ("calibration", "https://second-example.com/", 2),
        ("policy", "https://auth.first-example.com/", 3),
        ("policy", "https://third-example.com/", 4),
        ("test", "https://api.second-example.com/", 5),
        ("test", "https://fourth-example.com/", 1),
        ("test", "https://third-example.com/", 7),
        ("test", "https://clean-example.com/", 8),
    ]
    frame = pd.DataFrame([
        {
            **dict.fromkeys(FEATURE_COLUMNS, 0.0),
            "url_length": float(vector), "training_eligible": 1, "group_id": str(i),
            "split": split, "url": url, "label": 1, "label_quality": "generated_phishing",
        }
        for i, (split, url, vector) in enumerate(rows)
    ])

    isolated = isolated_splits(frame)

    assert isolated["policy"]["url"].tolist() == ["https://third-example.com/"]
    assert isolated["test"]["url"].tolist() == ["https://clean-example.com/"]
