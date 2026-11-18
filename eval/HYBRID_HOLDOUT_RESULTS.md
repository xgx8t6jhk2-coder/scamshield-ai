# ScamShield — full pipeline evaluation (rules + live checks + AI analyst)

File: `eval/holdout.json` · 150 samples · endpoint https://scamshield-ai-eaj.pages.dev/api/scan · 2026-11-18T18:05:33.083Z
Positive class = scam; suspicious and dangerous both count as positive. 0 request errors excluded.

| Accuracy | Precision | Recall | F1 |
| ---: | ---: | ---: | ---: |
| 85.33% | 85.86% | 91.40% | 88.54% |

| Actual | Predicted scam | Predicted benign |
| --- | ---: | ---: |
| Scam | 85 | 8 |
| Benign | 14 | 43 |

## Per language

| Language | n | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: |
| ar | 28 | 89.29% | 85.00% | 100.00% | 91.89% |
| en | 73 | 86.30% | 88.37% | 88.37% | 88.37% |
| mixed | 49 | 81.63% | 83.33% | 90.91% | 86.96% |

## AI analyst

AI opinion returned for 105 of 105 messages; it raised the verdict on 67.

## Latency (end-to-end, incl. network)

Median 3780 ms · p95 8669 ms
