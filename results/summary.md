# Results summary

## 1. Detection coverage (offline simulation)

Detection = an ACTIVE alert (rules: any rule hit) on the attack. 'covered' families are the five techniques simple stateless rules were written for; 'uncovered' ones are not. 95% Wilson intervals.

| family | live engine | batch scan 15 min | batch scan 60 min | stateless rules |
|---|---|---|---|---|
| covered | 150/150 = 100% [98-100] | 150/150 = 100% [98-100] | 150/150 = 100% [98-100] | 150/150 = 100% [98-100] |
| uncovered | 120/120 = 100% [97-100] | 120/120 = 100% [97-100] | 120/120 = 100% [97-100] | 0/120 = 0% [-0-3] |

Attribution (names the origin identity and the full path): live engine and batch scan: yes, stateless rules: never.

## 2. Model staleness: delay between the last attack step and the alert (seconds, simulation)

Excludes the CloudTrail delivery delay that every approach shares. Live = alert on arrival of the event.

| mode | n | median | p95 | mean ± 95% CI |
|---|---|---|---|---|
| batch 5 min | 270 | 171.0 | 284.1 | 157.7 ± 10.4 |
| batch 15 min | 270 | 523.2 | 866.8 | 475.9 ± 31.2 |
| batch 30 min | 270 | 907.4 | 1678.2 | 887.6 ± 61.1 |
| batch 60 min | 270 | 1595.7 | 3379.2 | 1663.7 ± 125.4 |
| live | 270 | 0.0 | 0.0 | 0.0 ± 0.0 |
| rules | 150 | 0.0 | 0.0 | 0.0 ± 0.0 |

Paired Wilcoxon signed-rank (live vs batch, same runs):

- batch 5 min: n=270, W=0.0, p=4.9e-46
- batch 15 min: n=270, W=0.0, p=4.9e-46
- batch 30 min: n=270, W=0.0, p=4.9e-46
- batch 60 min: n=270, W=0.0, p=4.9e-46

## 3. Fresh misconfiguration: time until a newly created dangerous path is known (seconds)

| mode | n | median | p95 | mean ± 95% CI |
|---|---|---|---|---|
| batch 5 min | 210 | 147.1 | 285.8 | 150.5 ± 12.1 |
| batch 15 min | 210 | 431.4 | 833.1 | 445.4 ± 36.0 |
| batch 30 min | 210 | 824.2 | 1692.4 | 856.8 ± 68.3 |
| batch 60 min | 210 | 1923.6 | 3388.4 | 1889.1 ± 135.1 |
| live | 210 | 0.0 | 0.0 | 0.0 ± 0.0 |

## 4. False alerts on a benign workload (about 90 events per run)

- live engine ACTIVE: mean 0.00 per run (max 0, 30 runs)
- live engine WATCH (ticket-level): mean 2.83 per run (max 3, 30 runs)
- batch 15 min ACTIVE: mean 0.00 per run (max 0, 30 runs)
- stateless rules: mean 23.00 per run (max 31, 30 runs)

## 5. Graph layer scaling (synthetic graphs; ms per single change)

| nodes | operation | exact update median / p95 | k-ball update median | full rebuild | nodes touched (exact, median / max) |
|---|---|---|---|---|---|
| 1000 | delete | 0.004 / 0.0078 | 0.1761 | 0.052 | 1 / 32 |
| 1000 | hub_insert | 0.0175 / 0.0547 | 1.7522 | 0.052 | 1 / 84 |
| 1000 | insert | 0.0041 / 0.0084 | 0.2483 | 0.052 | 1 / 5 |
| 1000 | new_admin_edge | 0.0096 / 0.0314 | 0.3672 | 0.052 | 5 / 455 |
| 10000 | delete | 0.0056 / 0.0143 | 0.3539 | 0.893 | 1 / 36 |
| 10000 | hub_insert | 0.0269 / 0.0659 | 18.3607 | 0.893 | 1 / 520 |
| 10000 | insert | 0.0059 / 0.0102 | 0.368 | 0.893 | 1 / 16 |
| 10000 | new_admin_edge | 0.0194 / 0.2312 | 0.3579 | 0.893 | 13 / 1521 |
| 50000 | delete | 0.0111 / 0.0223 | 0.5474 | 8.02 | 1 / 6 |
| 50000 | hub_insert | 0.0203 / 0.3137 | 75.2063 | 8.02 | 1 / 774 |
| 50000 | insert | 0.0116 / 0.0186 | 0.6609 | 8.02 | 1 / 4 |
| 50000 | new_admin_edge | 0.0415 / 0.1624 | 0.5836 | 8.02 | 27 / 431 |
| 100000 | delete | 0.0161 / 0.0268 | 0.8616 | 25.368 | 1 / 5 |
| 100000 | hub_insert | 0.0358 / 0.1556 | 152.9766 | 25.368 | 1 / 919 |
| 100000 | insert | 0.0168 / 0.0258 | 0.9276 | 25.368 | 1 / 8 |
| 100000 | new_admin_edge | 0.0488 / 1.1141 | 0.9463 | 25.368 | 19 / 1455 |

## 6. Engine scaling: one IAM event vs full re-derivation of all edges (synthetic accounts)

| principals | event type | event median ms | p95 ms | principals recomputed | full rebuild ms | speed-up |
|---|---|---|---|---|---|---|
| 50 | attach_policy_to_role | 0.365 | 0.497 | 1 | 15.3 | x42 |
| 50 | update_trust | 0.517 | 0.657 | 49 | 15.3 | x30 |
| 50 | add_user_to_group | 0.473 | 0.592 | 1 | 15.3 | x32 |
| 50 | policy_version_fanout | 1.579 | 1.722 | 3 | 15.3 | x10 |
| 50 | create_role | 0.8 | 1.34 | 65 | 15.3 | x19 |
| 100 | attach_policy_to_role | 0.683 | 1.147 | 1 | 59.0 | x86 |
| 100 | update_trust | 0.96 | 1.124 | 99 | 59.0 | x61 |
| 100 | add_user_to_group | 0.888 | 1.147 | 1 | 59.0 | x66 |
| 100 | policy_version_fanout | 3.415 | 3.743 | 4 | 59.0 | x17 |
| 100 | create_role | 1.334 | 1.847 | 115 | 59.0 | x44 |
| 200 | attach_policy_to_role | 1.348 | 1.57 | 1 | 228.3 | x169 |
| 200 | update_trust | 1.773 | 1.991 | 199 | 228.3 | x129 |
| 200 | add_user_to_group | 1.878 | 2.433 | 1 | 228.3 | x122 |
| 200 | policy_version_fanout | 5.902 | 6.404 | 4 | 228.3 | x39 |
| 200 | create_role | 2.453 | 3.111 | 215 | 228.3 | x93 |
| 400 | attach_policy_to_role | 7.296 | 8.047 | 1 | 911.0 | x125 |
| 400 | update_trust | 8.097 | 8.591 | 399 | 911.0 | x112 |
| 400 | add_user_to_group | 8.431 | 9.486 | 1 | 911.0 | x108 |
| 400 | policy_version_fanout | 27.113 | 27.833 | 8 | 911.0 | x34 |
| 400 | create_role | 9.836 | 10.773 | 415 | 911.0 | x93 |

## 7. Real AWS runs (deployed stack)

| scenario | runs | detected | rules detected | median total s | p95 total s | median delivery s | median queue s | median processing s |
|---|---|---|---|---|---|---|---|---|
| s1 | 30 | 30/30 = 100% [89-100] | 30/30 | 2.7 | 3.6 | 2.5 | 0.0 | 0.1 |
| s2 | 30 | 30/30 = 100% [89-100] | 30/30 | 2.5 | 4.5 | 2.4 | 0.1 | 0.1 |
| s3 | 30 | 30/30 = 100% [89-100] | 30/30 | 2.6 | 3.5 | 2.4 | 0.1 | 0.1 |
| s4 | 30 | 30/30 = 100% [89-100] | 30/30 | 19.2 | 30.6 | 19.0 | 0.1 | 0.1 |
| s5 | 30 | 30/30 = 100% [89-100] | 30/30 | 2.8 | 4.0 | 2.7 | 0.1 | 0.1 |
| x1 | 30 | 30/30 = 100% [89-100] | 0/30 | 2.6 | 3.3 | 2.4 | 0.0 | 0.2 |
| x2 | 30 | 30/30 = 100% [89-100] | 0/30 | 2.7 | 3.5 | 2.5 | 0.1 | 0.1 |
| x3 | 30 | 30/30 = 100% [89-100] | 0/30 | 2.7 | 3.6 | 2.6 | 0.1 | 0.1 |
| x4 | 30 | 30/30 = 100% [89-100] | 0/30 | 2.5 | 3.5 | 2.4 | 0.1 | 0.1 |

Batch scan runtime here: 146.32 s. A scheduled scan every T minutes detects a new state after T/2 + 146.3 s on average and T + 146.3 s at worst (plus the same CloudTrail delay):

- every 15 min: mean 596 s, worst 1046 s
- every 30 min: mean 1046 s, worst 1946 s
- every 60 min: mean 1946 s, worst 3746 s
