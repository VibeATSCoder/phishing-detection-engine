# JEV preview replay, 2026-11-18

All nine current preview scenarios returned usable HTML. Six matched their
frozen snapshots byte for byte. Digikala QR, Snapp Market app and Snapp Market
QR had changed. Both versions went through the local detector API using their
original URLs and the real RF/TCN and local JEV artifacts.

| Current scenario | RF/TCN combined score | Local JEV score | Auto-flag verdict |
| --- | ---: | ---: | --- |
| Digikala app | 0.314232 | 0.999600 | Phishing |
| Digikala links | 0.307899 | 0.999596 | Phishing |
| Digikala QR | 0.146731 | 0.999600 | Phishing |
| Filimo app | 0.366083 | 0.999581 | Phishing |
| Filimo links | 0.365949 | 0.999610 | Phishing |
| Filimo QR | 0.177406 | 0.999582 | Phishing |
| Snapp Market app | 0.327777 | 0.998471 | Phishing |
| Snapp Market links | 0.371866 | 0.997883 | Phishing |
| Snapp Market QR | 0.167017 | 0.999445 | Phishing |

| Mode | Current previews flagged / deferred | Frozen previews flagged / deferred | Legitimate controls cleared / deferred / flagged |
| --- | ---: | ---: | ---: |
| RF/TCN | 0 / 9 | 0 / 9 | 4 / 2 / 0 |
| RF/TCN + JEV guard | 0 / 9 | 0 / 9 | 1 / 5 / 0 |
| RF/TCN + JEV guard and auto-flag | 9 / 0 | 9 / 0 | 1 / 5 / 0 |

The six controls were archived legitimate pages from the same brand families.
They are regression controls drawn from multiple paper dataset splits.
Digikala.com cleared in auto-flag mode. Digikala.ir, Filimo.com, Snapp.ir,
Snappfood.ir and Snappshop.ir were deferred.

The API used static captures, simulated public DNS and no live domain facts.
The local auto-flag cases ended before the external reviewer. This run measures
the local decisions and deferrals without paying for model calls.

On the earlier 1,588-row isolated benchmark, auto-flag mode made 849 terminal
decisions. Of those, 842 were correct, for 99.2% accuracy on decided cases
with 53.5% decision coverage. There were 739 deferrals, including 49 of 654
generated phishing cases. The direct phishing detection rate was 92.5%.

Run the frozen replay from the detector repository:

```bash
PYTHONPATH=src python scripts/replay_preview_jev.py --scenario-dir /path/to/scenario_testset_2026-11
```

The script accepts a captured directory for the current previews and a paper
archive root for the six legitimate controls. The local JEV score is a model
score used by the threshold rule and has no calibrated probability guarantee.
