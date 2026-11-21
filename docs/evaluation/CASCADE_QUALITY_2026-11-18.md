# PersianPhish cascade quality, 2026-11-18

## RF/TCN release test split

The frozen RF and ONNX TCN were rerun on 1,780 official test feature rows
across 635 groups. This includes 935 verified legitimate rows and 845 generated
phishing rows. The eligible test groups are disjoint from eligible training,
calibration, and policy groups. Weak-feed records were excluded.

| Model | ROC AUC | Average precision |
| --- | ---: | ---: |
| Random Forest | 0.9933 | 0.9938 |
| TCN | 0.8593 | 0.9005 |
| Combined | 0.9935 | 0.9944 |

| Actual label | Cleared as legitimate | Sent onward as suspicious | Flagged as phishing |
| --- | ---: | ---: | ---: |
| Legitimate (935) | 472 (50.48%) | 462 (49.41%) | 1 (0.11%) |
| Generated phishing (845) | 3 (0.36%) | 205 (24.26%) | 637 (75.38%) |

The combined model ranks examples well on this split. The fast policy still
cleared three phishing rows. The row-level Wilson interval has an upper endpoint
of 1.04%, assuming independent rows. Correlation within groups can affect that
interval.

The replay used the archived feature vectors, the actual model artifacts, the
shipped thresholds, out-of-distribution gating, and the bootstrap corroboration
check. The live pipeline can recompute features from new crawl evidence and
apply origin scoring, allowlists, reputation, JEV, and reviewer decisions.
This result is for the frozen fast stage on the release split.

## Reference retrieval

Sixty-four captures were randomly sampled from all 1,016 PhishOracle archive
entries using seed 20261118. All sampled captures produced text and had a target
registrable domain in the index. The run used the reviewer's page extractor,
the first 4,000 characters of visible text, and real local bge-m3 embeddings.
Each pair of runs used the same query vector and index.

| Exact target present by rank | Dense baseline | Current hybrid |
| --- | ---: | ---: |
| Top 1 | 59/64 (92.19%) | 60/64 (93.75%) |
| Top 5 | 60/64 (93.75%) | 60/64 (93.75%) |
| Top 10 | 60/64 (93.75%) | 61/64 (95.31%) |

Hybrid moved one correct reference from third to first and recovered one
previous top-ten miss at rank eight. The other 62 target ranks were unchanged.
These are measures of brand retrieval among archived pages with indexed
targets. This archive has been used in earlier retrieval development.

The evaluation entry point is `scripts/evaluate_reference_sample.py` in the RAG repository. Run it in a
Python environment with both services' dependencies, a cached bge-m3 model, and
`RAG_INDEX_DIR` set to `Phishing_RAG_v2/Embedding_Index`. It accepts the archive
path and writes one result record per sampled case.

## Cascade regression tests

Thirteen new cases cover JEV score and confidence boundaries, high scores
in other risk categories, explicit abstention, missing configuration, provider
timeouts, simultaneous reviewer failure, and standalone clearances with
structural risk. They also verify that RF/TCN scores stay separate and a skipped
RF/TCN stage supplies no corroborating score to the reviewer.

All 234 detector tests and the release validator passed. JEV and the reviewer
are simulated in the new cascade tests. Live false-negative performance for
both stages remains unmeasured.

To reproduce the frozen model run from the detector checkout:

```bash
PYTHONPATH=src python scripts/evaluate_fast_stage.py
```
