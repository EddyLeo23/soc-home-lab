# Wazuh vs Microsoft Sentinel - same endpoint, three detections

One Windows 11 laptop feeds both SIEMs. Sysmon and the Wazuh agent send to a self-hosted Wazuh manager (VM).
Azure Arc with data collection rules (Security 4624/4625/4688/4740, Sysmon EID 1 and 13) sends to a Sentinel
workspace. Tests were controlled and run on 2026-10-15 and 2026-10-16. Evidence is in the screenshots folder,
the validation matrix and notes/build-log.md.

## Coverage

| Detection | Wazuh | Sentinel |
|---|---|---|
| T1098.003 privileged Azure role | Not visible: it is an Azure control-plane event, and Wazuh does not collect Azure logs in this lab | Custom scheduled rule; incidents #1 and #2 validated |
| T1110.001 repeated failed logons | No custom rule. Built-in 60122 (level 5, every single failure, MITRE T1531 in the alert) and 60204 (level 10, T1110, frequency 8 in 240 s) | Custom rule: 5 failures in a 10-minute sliding window, per account and host |
| T1547.001 Run key persistence | Custom rule 100101 (level 8) | Custom rule (Medium), port of 100101 |

## Detection latency (attack to alert)

| Test | Wazuh | Sentinel |
|---|---|---|
| T1110.001, live burst of 7 failures | first alert about 1 s | incident about 8.5 min (earlier bursts: about 9 and 10 min) |
| T1547.001, Atomic test 1 | alert about 1 s (15:40:31 to 15:40:32) | incident about 9 min and about 13.5 min (two runs) |
| T1098.003, role assignment | not applicable | incident about 13 min |

Wazuh evaluates events as they arrive. Sentinel's latency is mostly the 10-minute rule schedule: ingestion
took about 30-60 s in these tests. A shorter schedule would lower it; this was not tested.

## Behaviour on benign activity

- Failed logons: Wazuh raised level-5 alerts on single mistyped logons of the real user (3 alerts in 7 days).
  The Sentinel rule stayed silent below 5 failures. Sentinel saw 5 failures for the real user in the same
  period, so the 2-alert gap is not explained.
- Run key: both SIEMs alerted on a legitimate Microsoft Edge updater write (RunOnce value, run as SYSTEM).
  Neither rule has an allow-list. Sentinel also produced a duplicate incident for that one event (#7 after
  #6). It did not reproduce in a controlled repeat and the cause was not identified.

## Correlation

- Wazuh 60204 correlates by source IP. For local logons the IP is always ::1, so all local accounts share one
  counter. It did not fire on a live burst of 7, because its frequency is 8.
- Wazuh counts events by arrival time. When its server was off, queued events were delivered together and 60204
  counted failures from two bursts 50 minutes apart.
- The Sentinel rule counts by event time, per account and host, in a sliding window, and alerts only on events
  ingested since the last run.

## Alert context and operations

- Sentinel: mapped entities (account, host), custom details, dynamic alert titles, rules exported as ARM JSON.
  Gaps: the account that started the failed logons (Subject) is not mapped, and an array field renders raw
  in the alert description.
- Wazuh: alerts carry the full event, so the Subject account is visible. The 60122 alert is mapped to T1531,
  not to brute force.
- Sentinel needed engineering work that Wazuh did not: a workspace function to parse Sysmon, an ingestion-time
  dedup, and a fix for ingestion_time() returning empty after the parsing function reshaped the rows.
- Wazuh buffered events while its server was off and delivered them later, but alert times are then index times.
- Cost: Wazuh runs in a local VM. Sentinel ran on a free trial with a daily cap of 0.5 GB/day (actual volume
  about 3 MB/day). Post-trial pricing was not evaluated.

## Limitations

One endpoint, one lab, and small samples (1-3 measurements per latency figure). The attacks were simulated on
my own machine. For T1110.001 a purpose-built custom Sentinel rule is compared with Wazuh built-in rules, so
it is not like for like. Not tested: the High-severity path of T1098.003, and network or RDP failed logons.

## Takeaway

Wazuh was faster and gave per-event alerts. Sentinel gave controllable correlation and visibility of cloud
control-plane activity, at the cost of tuning and a 10-minute detection delay. Both need allow-lists for
legitimate Run-key writes. They complement each other here more than they compete.
