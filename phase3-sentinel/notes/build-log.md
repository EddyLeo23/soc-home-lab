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
