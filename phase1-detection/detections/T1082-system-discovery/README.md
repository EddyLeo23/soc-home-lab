# Detection: System Information Discovery via `systeminfo` (custom Wazuh rule)

| | |
|---|---|
| **MITRE ATT&CK** | T1082 System Information Discovery; tactic: Discovery |
| **Data source** | Sysmon Event ID 1 (process creation), SwiftOnSecurity config |
| **Wazuh rule** | Custom rule 100100, level 6 |
| **Endpoint** | Windows 11 laptop, Wazuh agent 4.14.8 |
| **Manager** | Wazuh 4.14.8 all-in-one on Ubuntu 22.04 (VirtualBox) |
| **Date tested** | 2026-10-08 |

## What I did

In a regular PowerShell window on the endpoint I ran a read-only command that collects host details (OS version, patches, hardware, network adapters):

```powershell
systeminfo
```

## The gap I found

My first assumption was that Wazuh's default rules would flag this. I checked rather than assumed:

1. Sysmon was logging the process. Querying the Sysmon event log directly with `Get-WinEvent` returned several Event ID 1 records for `systeminfo.exe`.
2. In the Wazuh alerts I reviewed, none was tied to those runs.

Sysmon was recording the activity, but the default Wazuh ruleset had no rule that turned it into an alert. That is a detection gap, and it is the useful result of this test.

## The fix: custom rule 100100

The rule matches Sysmon process-creation events whose image path ends in `systeminfo.exe` and tags them with T1082. The full rule is in `../../wazuh-manager/custom-rule-100100.xml`.

Process followed:

1. Backed up `local_rules.xml` before editing.
2. Validated the rules with `wazuh-analysisd -t` before restarting the manager.
3. Restarted the manager, re-ran `systeminfo`, and searched `rule.id: 100100`.

## Result

Rule 100100 fired on the next run. The alert shows the image path, the user, Medium integrity, and `powershell.exe` as the parent process, which identifies it as an interactive command and not background activity. A trimmed copy of the alert is in `alert-excerpt.json`.

## Limitations and next steps

- **Matching on the file path is easy to evade.** Copying and renaming the binary would avoid this rule. In this event `originalFileName` is `sysinfo.exe`, the name embedded in the executable itself, so a stronger version of the rule would also match on that field.
- **False positives.** Administrators run `systeminfo` legitimately. In a real environment I would raise severity only when it appears alongside other discovery commands from the same user in a short window, or from an unusual parent such as an Office application or a script host.
- **Level 6 is a starting point.** The right level depends on how common this command is in the environment, which needs baselining.
- Planned: add an `originalFileName` match, and test additional techniques (T1059, T1547).
