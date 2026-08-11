# Data Card

## V3 contract

The dataset distinguishes how a label was obtained. This field controls whether a row is allowed to train or formally evaluate the model.

| `label_quality` | Rows | Training eligible | Interpretation |
|---|---:|---|---|
| `verified_legitimate` | 7,434 | Yes | Unique healthy archived legitimate pages after the V3 quality gate |
| `generated_phishing` | 6,748 | Yes | Unique PersianPhish generated pages that passed the same gate |
| `weak_feed` | 759 | No | Deduplicated broad blocklist captures, retained only for stress analysis |

Total accepted rows: 14,941. Trusted training/evaluation rows: 14,182. Every accepted row has a unique canonical URL and sample identifier.

## Trusted split

| Split | Legitimate | Generated phishing | Purpose |
|---|---:|---:|---|
| Train | 4,899 | 4,448 | Fit the RF and TCN |
| Calibration | 756 | 678 | Probability calibration and ensemble calibration |
| Policy | 844 | 777 | Select operating thresholds |
| Test | 935 | 845 | One untouched final evaluation |

The stable split key is the legitimate source site's registrable domain. Its legitimate page and generated counterpart always stay together. No trusted registrable domain crosses splits.

## Label audit

The earlier "real phishing" archive was created from broad domain lists, not page-level phishing verification. It contained exact contradictions such as healthy `soft98.ir` and `linkdoni.soft98.ir` pages appearing as both legitimate and phishing. V3 therefore:

1. Quarantines weak-feed rows whose registrable domain exists in the verified legitimate corpus.
2. Deduplicates weak-feed URLs.
3. Excludes all weak-feed rows from fitting, calibration, policy selection, and formal accuracy metrics.
4. Reports only score distributions for the remaining weak stress set.

This prevents blocklist membership from being presented as page-level phishing truth.

## Quality audit

The extraction processed 15,865 candidates. The audit file contains 924 entries: 408 partial pages, 292 extraction errors, 94 blocked pages, 79 duplicate weak-feed URLs, 6 duplicate trusted canonical URLs, and 45 label conflicts. The source paper package and the model-ready subset serve different purposes: the model requires stricter URL validity and crawl-health checks, so not every paper sample is eligible for V3 training.

## Feature table

`realworld_v3_features.csv` includes provenance, source grouping, quality status, technique identifiers, and 85 numeric model features. The model artifact stores the feature order and refuses a schema mismatch.

## Known limitations

- Generated positives measure coverage of PersianPhish techniques, not all phishing found on the internet.
- The weak-feed stress set is not suitable for precision or recall claims.
- Domain age and popularity were unavailable for archived extraction and are represented with explicit missing indicators.
- A site can change after capture; verified benign history is corroborative, not permanent allowlisting.
- Open-world validation needs a larger, independently adjudicated, time-forward phishing corpus and at least tens of thousands of benign domains.
