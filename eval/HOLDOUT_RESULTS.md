# ScamShield evaluation

Engine 1.0.0 · 150 samples · Node v25.6.0

Corpus mix includes 68 scam messages, 37 benign messages, and 45 URLs.
The positive class is scam. Both suspicious and dangerous verdicts count as positive.

| Accuracy | Precision | Recall | F1 |
| ---: | ---: | ---: | ---: |
| 62.00% | 84.62% | 47.31% | 60.69% |

## Confusion matrix

| Actual | Predicted scam | Predicted benign |
| --- | ---: | ---: |
| Scam | 44 | 49 |
| Benign | 8 | 49 |

## Per-category recall

A dash indicates a zero denominator. Specificity measures the share of benign samples classified as benign.

| Category | Scam | Benign | Recall | Specificity |
| --- | ---: | ---: | ---: | ---: |
| aramex | 4 | 0 | 50.00% | — |
| bank-police | 4 | 3 | 50.00% | 100.00% |
| community | 0 | 4 | — | 25.00% |
| crypto | 4 | 0 | 50.00% | — |
| darb | 4 | 0 | 50.00% | — |
| delivery | 4 | 3 | 25.00% | 100.00% |
| dewa | 4 | 0 | 25.00% | — |
| emirates-id | 4 | 0 | 50.00% | — |
| emirates-post | 4 | 0 | 75.00% | — |
| etisalat-points | 4 | 0 | 50.00% | — |
| everyday | 0 | 4 | — | 100.00% |
| fake-charity | 4 | 0 | 75.00% | — |
| family | 0 | 4 | — | 100.00% |
| family-emergency | 4 | 0 | 50.00% | — |
| government | 0 | 3 | — | 66.67% |
| job-task | 4 | 0 | 0.00% | — |
| otp | 4 | 4 | 50.00% | 100.00% |
| salik | 4 | 0 | 25.00% | — |
| sextortion | 4 | 0 | 25.00% | — |
| traffic-fines | 4 | 3 | 0.00% | 66.67% |
| transport | 0 | 3 | — | 100.00% |
| uae-pass | 4 | 0 | 25.00% | — |
| url-disguise | 10 | 0 | 70.00% | — |
| url-lookalike | 15 | 0 | 66.67% | — |
| url-official | 0 | 20 | — | 85.00% |
| utility-telecom | 0 | 2 | — | 100.00% |
| work | 0 | 4 | — | 100.00% |

## Per-language metrics

| Language | Samples | TP | FP | FN | TN | Accuracy | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ar | 28 | 8 | 2 | 9 | 9 | 60.71% | 80.00% | 47.06% | 59.26% |
| en | 73 | 30 | 4 | 13 | 26 | 76.71% | 88.24% | 69.77% | 77.92% |
| mixed | 49 | 6 | 2 | 27 | 14 | 40.82% | 75.00% | 18.18% | 29.27% |

## Latency

Mean **0.429 ms** per item. Nearest-rank p95 **0.790 ms** per item.
Timing covers a single pass of individual engine calls and includes cold calls.

## False positives (8)

| Corpus ID | Type | Language | Category | Verdict | Score | Signals (weight) |
| --- | --- | --- | --- | --- | ---: | --- |
| ho-070 | message | ar | traffic-fines | suspicious | 45 | playbook_fake_fine (30) |
| ho-086 | message | en | community | dangerous | 77 | playbook_charity (18), link: lookalike (55) |
| ho-088 | message | mixed | community | dangerous | 68 | link: lookalike (55) |
| ho-089 | message | mixed | community | dangerous | 77 | playbook_charity (18), link: lookalike (55) |
| ho-096 | message | ar | government | suspicious | 41 | playbook_id_expiry (26) |
| ho-131 | url | en | url-official | dangerous | 67 | lookalike (55) |
| ho-132 | url | en | url-official | dangerous | 67 | lookalike (55) |
| ho-133 | url | en | url-official | dangerous | 67 | lookalike (55) |

## False negatives (49)

| Corpus ID | Type | Language | Category | Verdict | Score | Signals (weight) |
| --- | --- | --- | --- | --- | ---: | --- |
| ho-001 | message | en | traffic-fines | safe | 6 | — |
| ho-002 | message | ar | traffic-fines | safe | 6 | — |
| ho-003 | message | mixed | traffic-fines | safe | 3 | arabizi (0) |
| ho-004 | message | mixed | traffic-fines | safe | 3 | — |
| ho-005 | message | ar | salik | safe | 3 | — |
| ho-007 | message | mixed | salik | safe | 20 | playbook_fake_fine (11), arabizi (0) |
| ho-008 | message | en | salik | safe | 18 | asks_click (8) |
| ho-010 | message | ar | darb | safe | 6 | — |
| ho-011 | message | mixed | darb | safe | 3 | — |
| ho-015 | message | mixed | emirates-post | safe | 6 | — |
| ho-017 | message | ar | aramex | safe | 3 | — |
| ho-020 | message | en | aramex | safe | 6 | — |
| ho-021 | message | en | uae-pass | safe | 16 | playbook_id_expiry (9) |
| ho-022 | message | ar | uae-pass | safe | 16 | playbook_id_expiry (9) |
| ho-023 | message | mixed | uae-pass | safe | 16 | playbook_id_expiry (9), arabizi (0) |
| ho-027 | message | mixed | emirates-id | safe | 3 | arabizi (0) |
| ho-028 | message | en | emirates-id | safe | 6 | — |
| ho-030 | message | ar | dewa | safe | 3 | — |
| ho-031 | message | mixed | dewa | safe | 3 | arabizi (0) |
| ho-032 | message | mixed | dewa | safe | 14 | link: intent_words (6) |
| ho-035 | message | mixed | etisalat-points | safe | 3 | — |
| ho-036 | message | mixed | etisalat-points | safe | 14 | link: intent_words (6) |
| ho-039 | message | mixed | family-emergency | safe | 3 | arabizi (0) |
| ho-040 | message | mixed | family-emergency | safe | 3 | — |
| ho-041 | message | en | job-task | safe | 20 | playbook_job (11) |
| ho-042 | message | ar | job-task | safe | 20 | playbook_job (11) |
| ho-043 | message | mixed | job-task | safe | 3 | arabizi (0) |
| ho-044 | message | mixed | job-task | safe | 6 | — |
| ho-047 | message | mixed | crypto | safe | 3 | arabizi (0) |
| ho-048 | message | mixed | crypto | safe | 32 | link: intent_words (18) |
| ho-050 | message | ar | sextortion | safe | 3 | — |
| ho-051 | message | mixed | sextortion | safe | 3 | arabizi (0) |
| ho-052 | message | mixed | sextortion | safe | 3 | — |
| ho-055 | message | mixed | fake-charity | safe | 30 | playbook_charity (18), arabizi (0) |
| ho-059 | message | mixed | bank-police | safe | 3 | arabizi (0) |
| ho-060 | message | mixed | bank-police | safe | 24 | asks_click (8), link: intent_words (6) |
| ho-063 | message | mixed | otp | safe | 3 | arabizi (0) |
| ho-064 | message | mixed | otp | safe | 3 | — |
| ho-065 | message | en | delivery | safe | 6 | — |
| ho-066 | message | ar | delivery | safe | 3 | — |
| ho-067 | message | mixed | delivery | safe | 6 | — |
| ho-109 | url | en | url-lookalike | safe | 3 | — |
| ho-110 | url | en | url-lookalike | safe | 11 | intent_words (6) |
| ho-116 | url | en | url-lookalike | safe | 11 | intent_words (6) |
| ho-118 | url | en | url-lookalike | safe | 11 | intent_words (6) |
| ho-120 | url | en | url-lookalike | safe | 3 | — |
| ho-127 | url | mixed | url-disguise | safe | 3 | — |
| ho-128 | url | mixed | url-disguise | safe | 3 | — |
| ho-129 | url | en | url-disguise | safe | 34 | deep_subdomain (15), intent_words (6) |
