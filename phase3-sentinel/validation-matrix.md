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
| T1110.001 | 7 wrong passwords via runas against labtest - scheduled rule v0.3 (TimeGenerated = LastFailure) | Incident with real event time | Incident #4: First/Last activity 16:44:02 (matches the attempts), not the 1 h query window | Pass |
| T1547.001 | Atomic Red Team T1547.001 test #1 (reg add to HKCU Run key, removed right after) - scheduled rule | Incident created | Incident #5, Medium, ~9 min after the write (17:55:32 -> 18:04:32); title names the value; event time correct; Account + Host mapped | Pass |
| T1547.001 | 7 days of normal use before the rule existed (OneDrive and Epic Games Launcher already in the Run key) - query on Sysmon EID 13 | No match | Zero Run-key writes in the 7-day baseline; no false positive observed. Not tested: installer or updater writes, which would alert by design | Pass (limited) |

### Not yet tested

| Detection | Test case | Expected | Actual | Outcome |
|---|---|---|---|---|
| T1098.003 | Owner role assigned (High severity path of the dynamic severity logic) | Incident with High severity | Not tested - planned stretch item (needs an Owner assignment test) | Not tested |
| T1110.001 | Failed logons over the network (LogonType 3) or RDP (LogonType 10) | Match | Not tested - only interactive logons (LogonType 2) were simulated; the rule counts all types | Not tested |
| T1547.001 | Atomic test #1 repeated with the Wazuh server running (reg add, removed right after) - scheduled rule | One write gives one incident | Incident #8 only; one alert (generated 15:54 for an event at 15:40:31, ~13.5 min); Wazuh 100101 alert at 15:40:32 (~1 s) | Pass |
| T1110.001 | Live burst of 7 wrong passwords via runas against labtest with both SIEMs running (Sentinel rule v0.3 vs Wazuh built-in rules) | Sentinel incident; Wazuh alerts | Sentinel: incident #9, one incident, 8 min 43 s after the first failed logon (alert 17:13:15); Wazuh: 60122 x7 within seconds, 60204 did not fire (7 < frequency 8) | Pass |

