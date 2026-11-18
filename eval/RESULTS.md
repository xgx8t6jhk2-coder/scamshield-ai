# ScamShield evaluation

Engine 1.0.0 · 200 samples · Node v25.6.0

Corpus mix includes 90 scam messages, 50 benign messages, and 60 URLs.
The positive class is scam. Both suspicious and dangerous verdicts count as positive.

| Accuracy | Precision | Recall | F1 |
| ---: | ---: | ---: | ---: |
| 92.50% | 99.07% | 88.33% | 93.39% |

## Confusion matrix

| Actual | Predicted scam | Predicted benign |
| --- | ---: | ---: |
| Scam | 106 | 14 |
| Benign | 1 | 79 |

## Per-category recall

A dash indicates a zero denominator. Specificity measures the share of benign samples classified as benign.

| Category | Scam | Benign | Recall | Specificity |
| --- | ---: | ---: | ---: | ---: |
| aramex | 6 | 0 | 83.33% | — |
| bank-police | 6 | 0 | 100.00% | — |
| community | 0 | 5 | — | 100.00% |
| crypto | 6 | 0 | 100.00% | — |
| darb | 6 | 0 | 66.67% | — |
| delivery | 0 | 5 | — | 100.00% |
| dewa | 6 | 0 | 83.33% | — |
| emirates-id | 6 | 0 | 100.00% | — |
| emirates-post | 6 | 0 | 100.00% | — |
| etisalat-points | 6 | 0 | 100.00% | — |
| everyday | 0 | 5 | — | 100.00% |
| fake-charity | 6 | 0 | 50.00% | — |
| family | 0 | 5 | — | 80.00% |
| family-emergency | 6 | 0 | 66.67% | — |
| government | 0 | 5 | — | 100.00% |
| job-task | 6 | 0 | 83.33% | — |
| otp | 0 | 5 | — | 100.00% |
| salik | 6 | 0 | 100.00% | — |
| sextortion | 6 | 0 | 83.33% | — |
| traffic-fines | 6 | 5 | 100.00% | 100.00% |
| transport | 0 | 5 | — | 100.00% |
| uae-pass | 6 | 0 | 100.00% | — |
| url-disguise | 10 | 0 | 70.00% | — |
| url-lookalike | 20 | 0 | 100.00% | — |
| url-official | 0 | 30 | — | 100.00% |
| utility-telecom | 0 | 5 | — | 100.00% |
| work | 0 | 5 | — | 100.00% |

## Per-language metrics

| Language | Samples | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ar | 56 | 30 | 1 | 3 | 22 | 92.86% | 96.77% | 90.91% | 93.75% |
| en | 103 | 53 | 0 | 4 | 46 | 96.12% | 100.00% | 92.98% | 96.36% |
| mixed | 41 | 23 | 0 | 7 | 11 | 82.93% | 100.00% | 76.67% | 86.79% |

## Latency

Mean **0.369 ms** per item. Nearest-rank p95 **0.592 ms** per item.
Timing covers a single pass of individual engine calls and includes cold calls.

## False positives (1)

| Corpus ID | Type | Language | Category | Verdict | Score | Signals (weight) |
| --- | --- | --- | --- | --- | ---: | --- |
| ss-104 | message | ar | family | suspicious | 45 | tactic_payment_diversion (30) |

## False negatives (14)

| Corpus ID | Type | Language | Category | Verdict | Score | Signals (weight) |
| --- | --- | --- | --- | --- | ---: | --- |
| ss-017 | message | ar | darb | safe | 20 | playbook_fake_fine (11) |
| ss-018 | message | mixed | darb | safe | 20 | playbook_fake_fine (11) |
| ss-027 | message | mixed | aramex | safe | 3 | — |
| ss-048 | message | mixed | dewa | safe | 3 | — |
| ss-058 | message | en | family-emergency | safe | 33 | tactic_secrecy (20) |
| ss-060 | message | mixed | family-emergency | safe | 3 | — |
| ss-066 | message | mixed | job-task | safe | 3 | — |
| ss-077 | message | ar | sextortion | safe | 21 | playbook_romance_sextortion (12) |
| ss-079 | message | en | fake-charity | safe | 32 | playbook_charity (18) |
| ss-081 | message | mixed | fake-charity | safe | 30 | playbook_charity (18) |
| ss-084 | message | mixed | fake-charity | safe | 3 | arabizi (0) |
| ss-167 | url | en | url-disguise | safe | 33 | intent_words (12), no_https (8), defanged (0) |
| ss-169 | url | en | url-disguise | safe | 11 | intent_words (6) |
| ss-170 | url | ar | url-disguise | safe | 11 | intent_words (6) |
