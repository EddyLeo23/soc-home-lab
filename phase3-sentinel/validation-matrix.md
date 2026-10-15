# Validation matrix

| Detection | Test case | Expected | Actual | Outcome |
|---|---|---|---|---|
| T1098.003 | Monitoring Contributor + Log Analytics Contributor assigned to policy identity | No alert | No results | Pass |
| T1098.003 | Contributor assigned to lab-test-user via portal (v0.1 query) | Alert | No results - portal uses PascalCase fields | Fail -> fixed in v0.2 |
| T1098.003 | Contributor assigned to lab-test-user via portal (v0.2 query) | Alert | 1 row: Contributor, User, RG-SENTINEL-LAB | Pass |
| T1098.003 | User Access Administrator (unconstrained) assigned to lab-test-user via portal - scheduled rule | Incident created | Incident #1, Medium, ~13 min after the action | Pass |
| T1098.003 | UAA with "Recommended" condition assigned via portal - tuned rule | Incident with role in title, IP evidence | Incident #2: title shows UAA, IP entity mapped, ~13 min | Pass |
| T1110.001 | 7 wrong passwords via runas against local account labtest (draft query, threshold 5 / 10 min) | Match for labtest | labtest FailedCount 7 (first failure 15:14:39), query returns 1 row | Pass |
| T1110.001 | 2 mistyped-PIN failures at the lock screen within the same minute (draft query, threshold 5 / 10 min) | No match | No row for the real user; the pair stays below threshold | Pass |
| T1110.001 | 7 wrong passwords via runas against labtest - scheduled rule (threshold 5 / 10 min) | Incident created | Incident #3, Medium, ~9 min after the attack started (16:05 -> 16:14:08); dynamic title, Account + Host entities | Pass |
| T1110.001 | Earlier 15:14 burst still inside the 1 h lookback at the next rule run - scheduled rule | No duplicate incident | Only incident #3 created; newData filter suppressed the old burst | Pass |
