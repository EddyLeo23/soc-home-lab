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
