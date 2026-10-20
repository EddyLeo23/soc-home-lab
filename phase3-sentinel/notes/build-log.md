\# Phase 3 - Microsoft Sentinel build log



\## Setup

\- Resource group: rg-sentinel-lab (West Europe)

\- Workspace: law-sentinel-lab - North Europe (created 2026-10-12)

&#x20; - West Europe: rejected, region not accepting new customers (RequestDisallowedByAzure)

&#x20; - Spain Central: workspace created, but Sentinel could not be added (region not supported for Sentinel); deleted permanently and recreated

&#x20; - Resource group region is metadata only; workspace region can differ

\- Pricing tier: Pay-as-you-go (Per GB 2018)

\- Daily cap: 0.5 GB/day

\- Budget: EUR 5/month, alerts at 50% / 100% actual and 100% forecast

\- Billing: free account status pending confirmation (credit info not loading)



\## Sentinel

\- Enabled: 2026-10-12

\- Free trial: 2026-10-12 to 2026-11-12 23:59 UTC (10 GB/day free)

\- Milestone gate: day 24 = 2026-11-04 (core detections done or skip stretch)



\## Portal access

\- Sentinel used in the unified Microsoft Defender portal (security.microsoft.com)

\- Personal Microsoft account (MSA) sign-in failed against the default "Microsoft Services" tenant;

&#x20; fixed by signing in with the tenant-specific URL (?tid=<tenant ID>, not recorded here)

\- First KQL query run in Advanced hunting (2026-10-12)



\## Phase 2 - Azure Activity

\- Content hub: Azure Activity solution installed (1 connector, 14 rule templates, 15 hunting queries, 2 workbooks)

\- Connector policy assigned at subscription scope ("Configure Azure Activity logs to stream...")

&#x20; - First attempt scoped to the resource group by mistake; corrected - Activity Log export is subscription-level

&#x20; - Policy evaluation showed "Not started" (can take 30+ min)

\- Created diagnostic setting directly: activity-to-sentinel, all 8 categories -> law-sentinel-lab

\- Test event: tag project=sentinel-lab added to rg-sentinel-lab - ingestion confirmed in AzureActivity



\### Schema findings (T1098.003)

\- Operation value: MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE

\- Each action logs a Start row and a Success row

\- Role details (roleDefinitionId, principalType) exist only on the Start row, inside

&#x20; Properties\_d.requestbody as a JSON string - needs parse\_json(tostring(...))

\- Field names in requestbody are camelCase (properties.roleDefinitionId); KQL is case-sensitive

\- Success row has no request body -> joined Start + Success on CorrelationId + entity

\- First real role assignments observed: policy managed identity received

&#x20; Monitoring Contributor (749f88d5...) and Log Analytics Contributor (92aaf0da...)



\### Tests

\- Benign: privileged-role filter (Owner / Contributor / User Access Administrator) run over

&#x20; the two policy-identity assignments -> no results (expected: no alert)

\- Test user lab-test-user created in Entra ID at 15:31 (UPN not recorded)



\## Milestones

\- \[x] M1 - Workspace ready (2026-10-12)

\- \[x] M2 - Cloud detection validated (T1098.003) - 2026-10-13

\- \[x] M3 - Endpoint data verified - 2026-10-15

\- \[ ] M4 - Core done

\- \[ ] M5 - Stretch

\- \[ ] M6 - Close out

- Suspicious test: Contributor assigned to lab-test-user on rg-sentinel-lab via portal at 15:44
  - v0.1 query returned nothing: portal requestbody uses PascalCase, policy uses camelCase
  - v0.2 reads both with coalesce() -> 1 row (Contributor, User) - detection validated

### Analytics rule - Privileged Azure role assigned (T1098.003)
- Created 2026-10-12 as a Scheduled rule (not NRT): the rule joins Start + Success rows, which may
  arrive in different ingestion batches; NRT only sees newly ingested data and could miss the pair
- Runs every 15 min, looks back 1 h; ingestion_time() > ago(15m) on the Success row prevents duplicate alerts
- MITRE: Persistence + Privilege Escalation, T1098.003; severity Medium; incidents enabled, no grouping
- End-to-end test: UAA (unconstrained) assigned at 16:22:39 -> incident #1 created 16:35:34 (~13 min)
- Triage: incident assigned, set In Progress, tagged controlled-test
- Tuning after reviewing incident #1:
  - Analyst could not see which role was assigned -> added custom details (RoleName, PrincipalType)
    and dynamic alert title/description (description limited to 3 column parameters)
  - No IP evidence on incident -> IP entity was mapped to Caller instead of CallerIpAddress; fixed
- Re-test: UAA with "Recommended" condition assigned at 14:32 - result pending 

Endpoint: Windows 11 Home Single Language - Arc/AMA support uncertain, VM fallback planned


- Re-test result: incident #2 created 2026-10-13 14:45:47 (activity 14:32:22, ~13 min).
  Dynamic title shows role; IP entity now mapped; constrained (conditioned) UAA still parsed correctly
- Incidents #1 and #2 resolved: Informational, expected activity (security testing), tag controlled-test
- v1.0 (2026-10-13): added RBAC Administrator; dynamic severity via AlertSeverity column + property override.
  Severity override configured but not yet validated with a High-severity incident.
- DCR dcr-windows-security (Windows Security Events via AMA connector), custom XPath:
  Security EventIDs 4624, 4625, 4688, 4740 only - from DESKTOP-MLESSQ7
- Azure Monitor Agent installed via Arc automatically; Heartbeat confirmed
- Legacy "Security Events" connector shows green too (same SecurityEvent table) - not in use
- Enabled Process Creation auditing + command line in 4688 (auditpol + registry)
- First 72 h: 4624 x364, 4625 x2 (real mistyped logons - future T1110 benign case), 4688 x4387
- Volume: ~3 MB/day total (SecurityEvent ~2.2 MB/day) - under 1% of the 0.5 GB/day cap
- Cost check 2026-10-15: EUR 175.99 free credit untouched

### Sysmon DCR (dcr-sysmon) - created in Azure Monitor (no Sentinel connector for Sysmon)
- XPath: Microsoft-Windows-Sysmon/Operational, EventIDs 1 (process create) and 13 (registry value set)
- Data lands in the Event table (Source = Microsoft-Windows-Sysmon), not SecurityEvent
- Problem: DCR showed healthy ("Passed initial checks", all data flow validations OK) but 0 rows for 1 h+
  - Local agent config (mcsconfig.latest.xml) contained the rule -> Azure side fine
  - Agent log MonAgentHost.3.log: EvtSubscribe error 15007 "The specified channel could not be found"
  - Cause: leading whitespace before the channel name in the XPath (copy/paste artefact)
  - Fix: deleted and retyped the XPath -> Sysmon events arrived (31 in first check)
- Lesson: portal validation checks the configuration, not whether the channel exists on the host;
  the agent's own logs are the source of truth
- Sysmon_Parsed saved as a workspace function (first save went in as a saved query by mistake -
  saved queries can't be called by name; re-saved with "Save as function")
- Verified: Sysmon_Parsed returns parsed Image/CommandLine/IntegrityLevel in workspace Logs

### M4 - T1110.001 Repeated failed logons
- 2026-10-15: inspected real 4625 events on DESKTOP-MLESSQ7 (7 days): 5 failures, all <local-user>
  (username redacted), mistyped PIN/password at the lock screen
- Fields observed: LogonType 2 (interactive), Status 0xc000006d, SubStatus 0xc000006a (wrong password,
  account exists), FailureReason stored unexpanded as %%2313, IpAddress 127.0.0.1,
  LogonProcessName User32, AuthenticationPackageName Negotiate
- Design decisions:
  - Group by Computer + TargetUserName, threshold >= 5 in 10 min
  - Translate SubStatus in KQL (FailureReason is not human-readable as stored)
  - Entities: Account + Host; no IP entity for local logons (127.0.0.1)
  - Expect runas test to show LogonProcessName seclogo vs User32 for real lock-screen typos
- Benign baseline: 2 failures within the same minute (2026-10-15 13:36), below threshold
- 2026-10-15: created local test account labtest (standard user, group Users only) with
  'net user labtest * /add' - interactive password prompt so the password never appears in
  4688 command-line logs
- Lockout policy on the endpoint: threshold 10, duration 10 min, observation window 10 min
  -> test plan of 6-8 wrong passwords stays under the lockout limit (no 4740 expected)
- Cleanup item: remove labtest at the end of the project (net user labtest /delete)
- Draft KQL logic test (threshold 2): returned 1 row = the benign pair (13:36:39-13:36:41,
  FailedCount 2, LogonType 2, User32, wrong password); other 3 failures in separate windows, excluded
- Finding: LogonProcessName is stored with a trailing space ("User32 ") - use has/trim() in filters
- Known limitation: fixed bin(10m) can split a burst across a boundary (e.g. 3+3) and miss it;
  rule version to use a lookback window instead
- 2026-10-15 15:13 (local): attack simulation - 7 wrong-password attempts with
  'runas /user:DESKTOP-MLESSQ7\labtest cmd' (standard user, lockout threshold 10, no lockout expected)
  - Correct password never entered, so no 4624 expected for labtest
  - Expected in SecurityEvent: 7 x 4625, TargetUserName labtest, SubStatus 0xc000006a,
    LogonProcessName seclogo (to be verified)
  - Result: pending ingestion
- 2026-10-15 attack-test query (threshold 5, 2 h lookback): 1 row - labtest, FailedCount 7,
  first failure 15:14:39, all 7 inside one 10-min bin. No row for the real user (benign pair = 2)
- Screenshot: screenshots/05-t1110-attack-query.png (no username/email/IP visible)
- Note: draft is a query test only; the scheduled rule is not created yet
- Attack fields confirmed (screenshots/06-t1110-attack-fields.png): labtest 7 failures over 25 s
  (15:14:39 - 15:15:04), LogonType 2, LogonProcessName seclogo, SubStatus 0xc000006a (wrong password)
- Finding: runas and lock-screen typing are both LogonType 2; they differ by LogonProcessName
  (seclogo vs User32). Useful as context in the alert, but not used as a filter: a real attacker
  would not necessarily use runas, so the rule counts all logon processes
- Sliding-window version tested in Advanced hunting (threshold 5, window 10 min in 1-min steps,
  lookback/newData widened to 2 h for the test): 1 row - labtest, FailedCount 7,
  15:14:39 - 15:15:04, seclogo, wrong password; no row for the real user
- Finding: Security events were ingested ~30 s after the event (LatestIngest 15:15:36), much faster
  than the Azure Activity Log (~10-20 min). Rule: run every 10 min, lookback 1 h, newData 10 min
- Saved as detections/T1110.001-repeated-failed-logons.v0.2.kql (replaces the bin()-based draft)

### Analytics rule - Repeated failed logons (T1110.001)
- Created 2026-10-15 as a Scheduled rule, severity Medium, enabled
- MITRE: Credential Access, T1110 + T1110.001 (Password Guessing)
- Query: detections/T1110.001-repeated-failed-logons.v0.2.kql (sliding 10-min window, threshold 5)
- Schedule: every 10 min, lookback 1 h, alert when results > 0; newData filter (ingestion_time in the
  last 10 min) prevents repeat alerts for the same burst
- Entities: Account (Name = AccountName), Host (HostName = HostName); no IP entity (local logons)
- Custom details: FailedCount, LogonProcesses, FailureTypes, LastFailure
- Dynamic alert name and description with FailedCount, AccountName, HostName
- Incident creation enabled, alert grouping off, no automated response yet
- Screenshots: 07 entity mapping, 08 custom details, 09 scheduling
- Next: end-to-end test (new runas burst) and check that an incident is created
- 2026-10-15 16:05 (local): end-to-end test - 7 wrong-password attempts with
  'runas /user:DESKTOP-MLESSQ7\labtest cmd' (lockout threshold 10, correct password never entered)
  - Expected: scheduled rule runs within 10 min -> incident
    '7 failed logons for labtest on DESKTOP-MLESSQ7 (T1110.001)'
  - Dedup check: the earlier 15:14 burst must NOT produce an incident (outside newData window)
  - Result: pending
- Alert details checked (screenshots/11-incident-3-alert-details.png): FailedCount 7,
  LogonProcesses seclogo, FailureTypes wrong password, LastFailure 14:05:39Z (= 16:05:39 local, UTC+2)
  -> confirms incident #3 is the new burst, not the 15:14 one
- Impacted assets: 1 device, 1 user (labtest) - entity mapping confirmed end to end
- Known cosmetic issue: incident First/Last activity shows the query window (15:08-16:08), not the
  event times. Planned fix: set TimeGenerated = LastFailure in the rule query (v0.3)
- 2026-10-15: rule updated to v0.3 - added '| extend TimeGenerated = LastFailure' so the alert/incident
  uses the real event time instead of the query window (incident #3 showed 15:08-16:08)
- Query file: detections/T1110.001-repeated-failed-logons.v0.3.kql (v0.2 kept for history)
- Re-test pending: new runas burst, check incident First/Last activity matches the attempt times
- 2026-10-15 16:43 (local): v0.3 re-test - 7 wrong-password attempts with
  'runas /user:DESKTOP-MLESSQ7\labtest cmd' (correct password never entered)
  - Expected: new incident #4 within ~15 min; First/Last activity should match the attempts
    (16:43, seconds apart), not a 1-hour query window
  - Result: pending
- v0.3 re-test result (screenshots/12-incident-4-v03-times.png): incident #4 created, First/Last activity
  16:44:02 = LastFailure of the burst (v0.2 showed the 1 h query window) -> fix confirmed
- Known cosmetic issue: alert description renders the FailureTypes array raw: [_Wrong password (...)_];
  detection unaffected, left as is
- Detection latency (attempts 16:43-16:44 -> incident #4 linked 16:53:48): ~10 min; incident #3 ~9 min.
  Matches the 10-min schedule plus ~30 s ingestion. Screenshot: screenshots/13-incident-4-alert-details.png
- Incidents #3 and #4 resolved: Informational, expected activity (security testing), tag controlled-test
- 2026-10-15: rule exported as ARM template -> detections/T1110.001-repeated-failed-logons.rule.json
  (v0.3, detection as code; reviewed: no subscription/tenant ID, email, username or IP, workspace is a parameter)
- T1110.001 complete: sliding-window threshold rule, validated on benign (2 failures) and attack
  (7 failures x3 bursts) data, 9-10 min attack-to-incident, tagged t1110.001-v1.0

### M4 - T1547.001 Registry Run key persistence
- 2026-10-15: baseline check of Sysmon_Parsed over 7 days: EventID 1 = 795 events, EventID 13 = 65
  events (both arriving; screenshots/14-sysmon-eventid-counts.png)
- Run-key baseline: zero EID 13 events with TargetObject containing \CurrentVersion\Run in 7 days
  -> no benign Run-key writes to tune against yet; the test will be the first event
- EID 13 volume is low because the Sysmon config only logs security-relevant registry paths
- Plan: port Wazuh rule 100101 to KQL (Sysmon_Parsed, EID 13, TargetObject has \CurrentVersion\Run),
  test with Atomic Red Team T1547.001 + cleanup
- 2026-10-15 17:19 (local): Atomic Red Team T1547.001 test #1 run as the plain reg command:
  reg add HKCU\...\CurrentVersion\Run /v "Atomic Red Team" /d C:\Path\AtomicRedTeam.exe
  (payload file does not exist, so nothing can execute at logon)
- Cleanup: reg delete run immediately; Run key verified back to the original entries
  (OneDrive, EpicGamesLauncher) - no persistence left on the endpoint
- Sentinel received Sysmon EID 13 for the write: Image reg.exe, Details C:\Path\AtomicRedTeam.exe,
  User <local-user> (username redacted)
- Finding: Sysmon logs HKCU writes under HKU\<user-SID>\Software\..., not HKCU - the rule must
  match the \CurrentVersion\Run part of TargetObject, not the hive prefix
- The delete (Sysmon DeleteValue) is not collected: the DCR takes EID 1 and 13 only
- Wazuh comparison (rule 100101) and the KQL logic test: pending
- 2026-10-15: Sysmon_Parsed updated to v2 (replaced the saved function in Workspace Logs):
  added IngestTime column. ingestion_time() returns empty after the mv-apply/project reshaping
  (the Run-key rule query with an ingestion filter returned nothing), so it is now read before the
  reshaping and carried through. Rules use it for the newData dedup filter
- Verified: Sysmon_Parsed returns a filled IngestTime. Source: detections/Sysmon_Parsed.v2.kql
  (v1 kept as Sysmon_Parsed.kql for history)
- 2026-10-15: Run-key rule query tested on the Atomic event (lookback/newData widened to 2 h):
  1 row - Image reg.exe, ValueName Atomic Red Team, Details C:\Path\AtomicRedTeam.exe, IngestTime
  ~1 min after the write (17:19 -> 17:20:23). Confirms Sysmon_Parsed v2 IngestTime works
- Query saved as detections/T1547.001-run-key.kql (rule values: lookback 1 h, newData 10 min)
- Rule not created yet. Wazuh 100101 comparison pending (Wazuh server was off)

### Analytics rule - Registry Run key persistence (T1547.001)
- Created 2026-10-15 as a Scheduled rule, severity Medium, enabled
- MITRE: Persistence + Privilege Escalation, T1547 + T1547.001
- Query: detections/T1547.001-run-key.kql (Sysmon_Parsed v2, EID 13, TargetObject matches
  \CurrentVersion\Run or RunOnce); port of Wazuh rule 100101
- Schedule: every 10 min, lookback 1 h, alert when results > 0; newData filter on IngestTime
  (last 10 min) prevents repeat alerts
- Event grouping: one alert per event (each row is one registry write, so the title names each value)
- Entities: Account (Name = AccountName), Host (HostName = HostName)
- Custom details: ValueName, Payload (Details), Process (Image); TargetObject left out on purpose
  (contains the user SID)
- Incident creation enabled, alert grouping off, no automated response yet
- Screenshots: 15 entity mapping, 16 custom details, 17 scheduling
- Next: run the Atomic test again with the rule live, check the incident, then clean up
- 2026-10-15 end-to-end test: Atomic T1547.001 test #1 at 17:55, value deleted immediately, Run key
  verified back to the original entries. Incident #5 created 18:04:32 (~9 min); First/Last activity
  17:55:32 matches the write (the rule keeps the event's TimeGenerated, no v0.3-style fix needed)
- Custom details verified: ValueName Atomic Red Team, Payload C:\Path\AtomicRedTeam.exe,
  Process C:\WINDOWS\system32\reg.exe. Screenshots 18 and 19 (username redacted before commit)
- Incident #5 resolved: Informational, expected activity (security testing), tag controlled-test
- Known limitation: the rule has no allow-list - any Run/RunOnce write alerts (installers, updaters).
  Expected false-positive source; tuning idea: exclude known Image/ValueName pairs via a watchlist
- Pending: export the rule as JSON, tag t1547.001-v1.0, Wazuh 100101 comparison
- 2026-10-15: T1547.001 rule exported as ARM template -> detections/T1547.001-run-key.rule.json
  (detection as code; reviewed: no subscription/tenant ID, email, username or SID; the only scan hit
  was the @ of the KQL regex string)
- T1547.001 complete: Run/RunOnce write detection on Sysmon EID 13, validated with Atomic test #1
  (incident #5, ~9 min attack-to-incident), cleanup verified, tagged t1547.001-v1.0
- Three core detections done: T1098.003, T1110.001, T1547.001
- 2026-10-16: validation matrix reviewed (12 rows, 5 columns, no sensitive data). Added a
  'Not yet tested' section: T1098.003 High severity path, T1110.001 network/RDP logon types
- 2026-10-16 control test (Atomic T1547.001, 15:40, value deleted immediately, Run key verified clean):
  Sentinel produced 1 alert / incident #8 (event 15:40:31 -> alert 15:54, ~13.5 min); Wazuh rule
  100101 alerted at 15:40:32 (~1 s). Screenshots: 24 (Sentinel), 25 (Wazuh)
- Latency comparison: Sentinel 9-14 min (10-min schedule + ~1 min ingestion), Wazuh ~1 s
- Observed anomaly: incident #7 duplicated #6 (same Edge updater write, one record, ingested once).
  The two alerts came from consecutive runs (15:04, 15:14) with normal query windows; the 15:14 run
  should have filtered the 16-min-old event out. Cause not identified; not reproduced in the
  controlled test (1 write = 1 incident). #6 and #7 resolved as informational / expected activity

### Wazuh vs Sentinel - T1110.001 findings (2026-10-16)
- Wazuh covers failed logons with two BUILT-IN rules (no custom rule): 60122 (level 5, fires on every
  single 4625; MITRE in the alert is T1531) and 60204 (level 10, T1110: frequency 8, timeframe 240 s,
  same_field win.eventdata.ipAddress). 24 hits in 7 days: 22 x 60122 + 2 x 60204
- 60122 counts: 19 for labtest, 3 for the real user's mistyped PINs (Sentinel saw 5 failures for the
  real user in the same period: gap of 2 not explained). Screenshots 26, 27, 28
- Wazuh alerts on benign single typos (level 5); the Sentinel rule is silent below 5 in 10 min
- 60204 groups by source IP; for local logons the IP is always ::1, so all local accounts share one
  counter. Sentinel groups by account + host
- The 60204 alert counted events from two bursts 50 min apart: the agent delivered the queued events
  within seconds (server was off) and Wazuh correlates by arrival time. Sentinel uses the event time
- Untested: with frequency 8, a live burst of 7 failures may not trigger 60204
- Sentinel rule gap: it maps only the target account. The raw 4625 also has the Subject account (who ran
  runas) and the caller process (svchost.exe); not shown in the incident. Possible v1.1
- The raw Wazuh alert JSON and the CSV exports contain the local username and user SID: not committed
- 2026-10-16 17:04 live burst (7 wrong passwords via runas against labtest, Wazuh server running):
  - Wazuh 60122 (level 5): 7 alerts, 17:04:33 - 17:04:53 (first alert within seconds of the start);
    screenshot 29
  - Wazuh 60204 (Multiple Windows Logon Failures, level 10, frequency 8): did NOT fire (7 < 8);
    screenshot 30
  - Wazuh built-in rules therefore alert on each failure at level 5 (MITRE T1531 in the alert), but its
    brute-force correlation missed a 7-failure burst that the Sentinel rule (threshold 5 / 10 min) catches
  - Wazuh latency for this burst: seconds. Sentinel: pending (10-min schedule)
- 2026-10-16 17:04 live burst, both SIEMs running: Sentinel burst 17:04:32-17:04:52, ingested 17:05:19,
  alert generated 17:13:15 -> incident #9 (~8.5 min from the start of the burst), First/Last activity
  17:04:52 (event time correct). Wazuh 60122 first alert 17:04:33 (~1 s). Screenshots 31, 32
- Sentinel attack-to-incident across the three T1110.001 tests: 8.5-10 min; Wazuh: seconds
  (the 10-min schedule contributes; with ingestion of ~30-60 s it does not fully explain 8.5-13.5 min; not investigated)
- Incident #9 resolved: Informational, expected activity (security testing), tag controlled-test
- Next: write comparison/wazuh-vs-sentinel.md from these results
- 2026-10-16: comparison/wazuh-vs-sentinel.md written (coverage, latency, benign behaviour, correlation,
  operations, limitations). Sources: validation matrix, screenshots 14-32, build log

- 2026-10-16: comparison doc edited after review: figures labelled as observed measurements; schedule
  no longer presented as the full explanation of Sentinel latency; alert/incident terms made consistent;
  "2-alert gap" reworded as an unexplained discrepancy; title now "one endpoint, both SIEMs"
- 2026-10-16: correction - live-burst latency is 8 min 43 s from the first failed logon (17:04:32) to alert
  creation (17:13:15), not ~8.5 min; fixed in the matrix and the comparison (earlier log lines keep the
  rounded figure). IR-001 finalized as the v0.3 artifact: Observed / Corroborated / Not established labels,
  four distinct timeline times, event notes, severity vs disposition, four-step hypothetical response,
  detection parameters and blind spots, v0.4 stretch item with acceptance criteria
- 2026-10-16: phase3-sentinel/README.md created (environment, detections, validation, results, lessons,
  limitations, status). Cost section left to be completed at close-out
- 2026-10-16: README cost section completed: EUR 0.04 incurred this month, EUR 175.96 credit left (day 5).
  Screenshot: screenshots/33-azure-cost.png. Credit expires about 2026-11-10, before the Sentinel trial ends
  (2026-11-12); spending limit on, never upgrade

- 2026-10-16: fixed a naming mistake - the cost screenshot was committed as screenshots/-azure-cost.png
  (a formatting error left the number empty); renamed to screenshots/33-azure-cost.png and the README and this log updated
- 2026-10-16 18:53 (local): Owner test for the High severity path of T1098.003 - Owner role assigned to
  lab-test-user at resource-group scope (rg-sentinel-lab) with the 'all roles except privileged administrator
  roles' condition, then removed immediately
  - Expected: incident with Owner in the title and severity High (UAA tests #1 and #2 were Medium although UAA
    is High in the rule's table: either they predate dynamic severity, or the override does not take effect;
    alertSeverityColumnName = AlertSeverity is set in the exported rule)
  - Result: pending
- 2026-10-17 18:43 (local): regression test for rule v1.1 - Contributor assigned to lab-test-user at
  resource-group scope, then removed immediately. Expected: incident with Contributor in the title, Medium,
  custom detail PrincipalType = User. Result: pending
- 2026-10-17: T1098.003 rule v1.1 (text-only edit, query unchanged): the custom detail key RoleName was mapped
  to the column PrincipalType (incident 10 showed RoleName: User for an Owner assignment); key renamed to
  PrincipalType. Rule description updated to list all four roles in the table (it listed three).
  Screenshot: screenshots/35-t1098-custom-details-v1.1.png (the file name has a dot, not an underscore)
- Note: commit 79b6c5a (message: regression test executed, Contributor) also contains screenshots 34 and 35,
  because git add swept them in; history not rewritten
- 2026-10-16 Owner test result: incident 10, High, Owner in the title (screenshots/34-incident-10-owner-high.png,
  email, IP and user label redacted). Event 18:52:58 -> incident created 19:14:15 = 21 min 17 s (earlier
  T1098.003 tests: about 13 min); the difference is unexplained. The High path works with Owner. Incidents 1 and 2
  (UAA, Medium although UAA is High in the table) most likely predate dynamic severity; not proven, UAA not retested
- Matrix repaired: rows appended after the Not yet tested section had landed under that table; Pass rows moved to
  the main table, Owner row added, the Owner not-tested row removed
- 2026-10-17: correction - the entry above saying the matrix was repaired was premature: commit 0e6b33b did not
  change validation-matrix.md. The repair is made in this commit: the two Pass rows that had landed under
  'Not yet tested' (Wazuh-running Atomic repeat, live burst of 7) moved to the main table, the Owner Pass row
  added, the Owner not-tested row removed; only the network/RDP row stays under 'Not yet tested'
- 2026-10-19: cause of the failed Contributor assignment found in the Activity log error: HTTP 409 Conflict,
  RoleAssignmentExists - lab-test-user still had Contributor at resource-group scope from the M2 tests, and Azure
  rejects a duplicate assignment. The rule never saw an event, so the rule v1.1 edit is still unvalidated. Fix:
  remove the leftover assignment, then repeat the test. The raw error JSON contains the subscription and tenant
  IDs, an email, a name and a public IP and is not committed
- 2026-10-19: correction - the previous entry named a leftover Contributor assignment as the cause of the failed
  test of 2026-10-17. The Activity log error (HTTP 409, RoleAssignmentExists) says a role assignment already
  existed but not which role, and the current IAM list for rg-sentinel-lab shows lab-test-user with User Access
  Administrator and no Contributor. The role used in the failed attempt is being checked from the request body
- 2026-10-19 17:33 (local): rule v1.1 regression test - Contributor assigned to lab-test-user at resource-group
  scope (this time the assignment succeeded). Incident 13, Medium, Contributor in the title; event 17:33:17 ->
  incident created 17:43:30 = 10 min 13 s (T1098.003 so far: 10 min 13 s, about 13 min, 21 min 17 s; spread not
  explained). Screenshot: screenshots/37-incident-13-contributor-medium.png (email, IP and user label redacted)
- Still to confirm: the alert custom detail reads PrincipalType (the v1.1 change); not yet seen
- 2026-10-19: screenshots/38-incident-13-alert-details.png added (alert details of incident 13: Custom Details
  PrincipalType: User; email, username and user label redacted). Evidence for the rule v1.1 validation
- 2026-10-19: rule v1.1 validated. Incident 13 (Contributor, Medium): the alert custom detail now reads
  PrincipalType: User (incident 10 showed RoleName: User for the same column), and the portal rule description
  lists the four roles. Event 17:33:17 -> incident created 17:43:30 = 10 min 13 s. T1098.003 latency so far:
  10 min 13 s, about 13 min, 21 min 17 s - the spread is not explained
- Still unexplained: the failed attempt of 2026-10-17 returned 409 RoleAssignmentExists although the IAM list
  showed no Contributor for lab-test-user. The screenshot of the alert custom details (email and username
  redacted) is committed separately
- 2026-10-19: the matrix row for the rule v1.1 test (incident 13, Contributor, Medium, PrincipalType: User,
  10 min 13 s) was not included in commit 41e0ccf and is added in this commit
- 2026-10-19: T1098.003 rule re-exported as v1.1 -> detections/T1098.003-privileged-role.rule.json (detection as code
  now matches the live rule). Changes since v1.0, text only, query unchanged: custom detail key PrincipalType
  (was RoleName), rule description lists the four roles. Reviewed: no subscription/tenant ID, email, IP or
  username (the IP check first matched the template's contentVersion 1.0.0.0, a false positive of my check).
  Validated by incident 13 (Contributor, Medium, PrincipalType: User). v1.0 stays reachable through the tag
  t1098.003-v1.0
- 2026-10-19 ~18:18 (local): boundary test, part 1 - 4 wrong passwords via runas against labtest. The hunting query
  returned exactly 4 x 4625 (SubStatus 0xc000006a, seclogo), all ingested at 18:18:36, so the events were
  available for the rule to count. Expected result: no alert (threshold is 5). Screenshot:
  screenshots/39-t1110-boundary-4-failures.png (no username or IP; labtest only). Result of the wait pending
- 2026-10-19: Run-key rule false positives, second batch (incidents 11 and 12): the Microsoft Edge/EdgeWebView
  updater (setup.exe, user SYSTEM, version 155.0.4283.62) wrote an msedge_cleanup_{GUID} RunOnce value, a different
  GUID from incidents 6 and 7 (Copilot installer, version .60). Same pattern: a browser update schedules cleanup of
  old versions. Four incidents from two updater runs; the rule has no allow-list. Whether 11 and 12 are two alerts
  for one write (as 6 and 7) was not verified. Screenshot: screenshots/40-fp-edgewebview-alert.png (no username
  or IP). Resolved as informational / expected activity, not tagged as a test
- Tuning idea (not implemented): allow-list by Image path under Program Files\Microsoft\Edge* plus a ValueName that
  starts with msedge_cleanup_, and keep alerting on the same value name from any other path
- 2026-10-19: Run-key rule false positives, second batch (incidents 11 and 12): the Microsoft Edge/EdgeWebView
  updater (setup.exe, user SYSTEM, version 155.0.4283.62) wrote an msedge_cleanup_{GUID} RunOnce value, a different
  GUID from incidents 6 and 7 (Copilot installer, version .60). Same pattern: a browser update schedules cleanup of
  old versions. Four incidents from two updater runs; the rule has no allow-list. Whether 11 and 12 are two alerts
  for one write (as 6 and 7) was not verified. Screenshot: screenshots/40-fp-edgewebview-alert.png (no username
  or IP). Resolved as informational / expected activity, not tagged as a test
- Tuning idea (not implemented): allow-list by Image path under Program Files\Microsoft\Edge* plus a ValueName that
  starts with msedge_cleanup_, and keep alerting on the same value name from any other path
- 2026-10-19: boundary test, part 1 result - after 4 failed logons (about 18:18, ingested 18:18:36) and a wait
  until after 18:44 (two to three rule runs) the SecurityAlert query for the failed-logons rule returned no rows:
  4 failures stayed below the threshold of 5, no alert (reported by the lab owner; the empty result screen was not
  kept). Part 2 (exactly 5 failures, alert expected) follows
- 2026-10-19: boundary test result for the failed-logons rule (v0.3): 4 failures (18:18) gave no alert; exactly 5
  failures (18:49:35) gave incident 15, Medium, created 19:03:56 (alert 19:03:35, 14 min 0 s after the failures,
  although the events were ingested at 18:49:57; the longest latency measured for this rule and not explained).
  The threshold fires at 5 and not at 4: no off-by-one error. Screenshots: 42 (incident), 43 (alert details),
  41 (the 5 events); 39 for the 4 events. Incident 15 resolved as informational / security testing
- 2026-10-19: README: Architecture section added (Mermaid diagram: endpoint, Azure Arc and data collection rules,
  Log Analytics, Sysmon_Parsed v2, three analytics rules, incidents; Azure Activity log for T1098.003; Wazuh as the
  comparison path)
- 2026-10-20 ~15:05 (local): telemetry freshness check (7 days): AzureActivity 338 events, last 13:48 (16 min
  earlier); Event (Sysmon) 7188, last 2026-10-19 21:50; SecurityEvent 20564, last 2026-10-19 21:50 (974 min earlier).
  Both laptop sources stopped at the same time, consistent with the laptop being off or offline overnight (not
  confirmed). Screenshot: screenshots/44-telemetry-freshness.png (table names, counts, times only)
- Observation: the endpoint rules (T1110.001, T1547.001) cannot detect anything while the laptop sends nothing, and
  no rule alerts on the silence itself. Documented as a blind spot; a source-silent rule is a possible next step
- 2026-10-20: billable ingestion over the last 7 days (Usage table): SecurityEvent 0.81-5.66 MB/day, Event (Sysmon)
  4.39-10.69 MB/day; highest day 2026-10-18, about 14.3 MB in total, under 3% of the 0.5 GB/day cap. No rows for
  2026-10-17 (a test day; cause not checked) or for the partial day of 2026-10-20. Screenshot:
  screenshots/45-ingestion-volume.png
- Correction: the earlier figure of about 3 MB/day in the README is out of date; the observed range once Sysmon was
  flowing is about 6-14 MB/day. To fix in the close-out. Cost so far unchanged (EUR 0.04 on day 5)
- 2026-10-20: README: Telemetry reliability section added (source freshness, the overnight silence of the laptop
  sources confirmed by the lab owner as the laptop being off, no alert on silence, ingestion volume, IngestTime).
  Corrected the volume figure in the Environment section (about 3 MB/day -> observed 1-14 MB/day)
- 2026-10-20: AI-triage extension to Sentinel incidents, step 1 (samples and labels, no model run yet). Five alert
  samples in phase2-pipeline/ai-triage/samples-sentinel/, reconstructed from the incident custom details (incidents 15,
  9, 8, 6, 11); no username, IP, email or ID. Labels fixed BEFORE any run: T1110 5 and 7 failed logons = suspicious
  (simulated password guessing); Atomic Red Team Run-key write = suspicious (an easy case: the value name and payload
  say Atomic Red Team); Edge/Copilot and EdgeWebView updater writes = benign (real updates). Incidents 10 and 13 were
  left out (email and public IP). Known limitation: the Phase 2 prompts name Sysmon fields (integrityLevel,
  currentDirectory, parentImage) that these alerts do not carry; the prompt will not be changed
- 2026-10-20: AI-triage extension, step 2: phase2-pipeline/ai-triage/ai_triage_sentinel.py created as an edited copy of
  ai_triage.py (the original is untouched). Changes: labels for the five Sentinel samples (committed before any run),
  input folder samples-sentinel, results prefix results-sentinel-, utf-8-sig reading (the sample files carry a BOM),
  the key note is stripped as well, and rule_id handles a plain rule name. Prompts unchanged, including the
  'Wazuh alert' wording. No model run yet
- 2026-10-20: AI-triage extension, step 3: three runs on the five Sentinel alerts, committed as written by the script
  (the My review sections are still placeholders). gemma3:4b guided 3/5 (false positives on both Edge updater writes,
  citing a high integrity level that the alert does not carry); llama3.2:3b guided 3/5 (false negatives on both
  failed-logon alerts); llama3.2:3b basic 2/5 (benign on everything, including the Atomic Run-key write, with an
  invented scheduled task). Results files: results-sentinel-<variant>-<model>.md/.json in phase2-pipeline/ai-triage.
  Five alerts, one run per configuration: an illustration, not a benchmark
- 2026-10-20: AI-triage extension write-up moved to its own file: phase2-pipeline/ai-triage/README-sentinel-extension.md
  (same content, own headings); README.md keeps a short pointer under 'Sentinel extension'. Findings still cover only
  the reasoning read so far (three of five alerts per run). The My review placeholders in the result files are empty
- 2026-10-20: latency wording corrected in the README and the comparison (earlier log lines keep their wording as
  history): the T1098.003 rule runs every 15 minutes, the other two every 10; the boundary test latency (14 min 0 s) added
  to the T1110.001 rows; the range stated as 8 min 43 s to 21 min 17 s (about 9-21 minutes) instead of 9-14; the
  comparison no longer calls 13.5 min the longest measurement. Causes of the spread still not investigated
- 2026-10-20: README-sentinel-extension.md revised after a review: overview split into purpose, method and limitation,
  key finding limited to this test, labels described as my own assessment, run details (model IDs, prompts, commits),
  missed vs wrongly flagged counts per run, an evidence audit of the 9 explanations read (6 unread), the placeholder
  Account value 'user session' disclosed, output validation and untested prompt injection listed as limitations. Script,
  samples and results untouched. Not done yet: Sentinel-specific prompt variant, gemma3:4b basic run, validation,
  more varied alerts, audit of the other six explanations
- 2026-10-20: ai_triage_sentinel.py small fixes made AFTER the runs (results unchanged; behaviour for the five labelled
  samples unchanged): the argparse description says Sentinel instead of Wazuh, and the script exits before scoring if a
  sample has no label in EXPECTED (before, an unlabelled sample was scored as a mismatch). The results were produced by
  the earlier version (6c2782b). Output validation (required keys, permitted values) is not added here: it goes into the
  next version with the Sentinel-specific prompt, which needs new runs anyway
- Found while reviewing: the Run-key sample descriptions in samples-sentinel are my own wording, not Sentinel's alert
  text (the real format is '{ValueName} set to {Details} by {Image} in a Run/RunOnce key.'); the README will list what
  was taken from the incidents and what I wrote
- 2026-10-20: README-sentinel-extension.md: commit order stated with times (425c480 14:20 samples and labels as text,
  6c2782b 14:26 script with labels in code, 778572b 14:41 results, f188f06 15:17 later script fix; committing computer's
  clock, order of commits only) and a Reconstruction details table added (what came from each incident, what I wrote or
  changed, what is not included). Disclosed: Run-key sample descriptions are my own wording, Account 'user session' is a
  placeholder, LogonTypes [2] for the 5-failure sample is assumed
- 2026-10-20: data collection rules exported as ARM templates -> infrastructure/dcr-windows-security.template.json and
  dcr-sysmon.template.json (found by content in Downloads). The subscription ID in the workspace defaultValue is
  replaced by <subscription-id>; scanned for GUIDs, tenant ID, email, username and IPs (none left). Not included: the
  rule-to-machine association, the Arc agent, the Sysmon install and config. The downloaded originals still contain the
  subscription ID and are not committed
- 2026-10-20: cleanup step 1: the matrix's Not yet tested table now also lists User Access Administrator and RBAC
  Administrator on rule v1.1 (not tested; the same lookup table gave the expected severity for Owner and Contributor).
  Decision: no further role tests before removing the test accounts
- 2026-10-20: cleanup step 2: the local test account labtest was deleted with 'net user labtest /delete' (completed
  successfully); 'net user' afterwards lists no labtest. Screenshot not kept (it shows the local username). Next: the
  Azure test user lab-test-user and its role assignments
