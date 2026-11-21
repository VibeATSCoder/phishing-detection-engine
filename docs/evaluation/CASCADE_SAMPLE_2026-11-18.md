# PersianPhish cascade sample, 2026-11-18

The detector API processed 15 archived pages in each of three configurations.
The sample included all nine frozen phishing scenarios and six legitimate
controls drawn from distinct brands in the archived paper test split with
random seed 17. The replay used archived browser evidence with simulated DNS
and domain facts in an isolated Docker network.

The detector used its bundled RF/TCN artifacts. The reviewer and RAG service
used the current local source, and retrieval used the actual 481,235-block
bge-m3 index. The JEV endpoint returned fixture scores, and the packaged
reviewer model mock returned suspicious from both passes.

| Configuration | JEV completed | Reviewer completed | Reviews with references | Legitimate controls cleared | Phishing cases left suspicious |
| --- | ---: | ---: | ---: | ---: | ---: |
| RF/TCN, then review | 0/15 | 12/15 | 12/12 | 3/6 | 9/9 |
| RF/TCN, JEV, then review | 15/15 | 13/15 | 13/13 | 2/6 | 9/9 |
| JEV, then review | 15/15 | 15/15 | 15/15 | 0/6 | 9/9 |

All 40 submitted reviews completed and each returned three references. The
reviewer mock's abstention accounts for the unresolved verdicts. The sample
measures routing, provider compatibility and retrieval integration. Real
decision-model detection accuracy, false-negative rate and threshold selection
require a labeled evaluation with the selected provider.

The separate frozen-scenario retrieval run returned the expected exact brand
in the top five for all six scenarios with an indexed target, including three
at rank one. All three Snapp Market scenarios returned a Snapp family reference
at rank one. The exact Snapp Market domain is absent from the index.
