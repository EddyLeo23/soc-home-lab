# Detection: Persistence via registry Run key (custom Wazuh rule)

| | |
|---|---|
| **MITRE ATT&CK** | T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder; tactics: Persistence, Privilege Escalation |
| **Data source** | Sysmon Event ID 13 (registry value set), SwiftOnSecurity config |
| **Wazuh rule** | Custom rule 100101, level 8, child of built-in rule 92300 |
| **Endpoint** | Windows 11 laptop, Wazuh agent 4.14.8 |
| **Manager** | Wazuh 4.14.8 all-in-one on Ubuntu 22.04 (VirtualBox) |
| **Date tested** | 2026-10-08 |

## What I did

In a regular (non-admin) PowerShell window I added a harmless autostart entry that launches Calculator, then removed it after the test:

```powershell
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "TestPersist" -Value "C:\Windows\System32\calc.exe" -PropertyType String
```

## What fired

Rule 100101 raised a level 8 alert. The event shows the registry path that was written, the value (`calc.exe`), the event type (`SetValue`), and `powershell.exe` as the process that made the change. A trimmed copy is in `alert-excerpt.json`.

The Sysmon configuration tags this event with `RuleName: T1060,RunKey`. T1060 is the legacy ATT&CK ID for this technique, which was later merged into T1547.001, so the config's label and Wazuh's mapping refer to the same behaviour.

## What went wrong first, and how I narrowed it down

My first version of the rule produced no alert at all. Rather than guess, I ruled out one layer at a time:

1. **Is Sysmon logging it?** Yes. Querying the Sysmon log with `Get-WinEvent` returned Event ID 13 records for the `TestPersist` value.
2. **Does the event reach the manager?** Yes. With archive logging temporarily enabled on the manager, the raw event appeared in the archives with the expected registry path.
3. **Is my pattern wrong?** No. A temporary rule with no pattern at all (any Sysmon registry-value event) fired on other registry changes, but not on this one.
4. **Can I replay it with `wazuh-logtest`?** Not reliably. logtest decodes Windows event-channel events with the generic JSON decoder, so the Windows rules never match and the result tells you nothing about the live pipeline.
5. **Is a built-in rule involved?** Yes. Rule 92300 in `0860-sysmon_id_13.xml` is level 0, tagged T1547.001, and matches Run-key writes. A level-0 rule matches silently and raises no alert. My rule sat beside it as a sibling and never got a turn, which is consistent with Wazuh using the first matching rule at a given level.

An early search of the built-in rules had missed 92300 because the rule file escapes backslashes differently from the pattern I searched for.

**Fix:** make the custom rule a child of 92300 (`<if_sid>92300</if_sid>`). It then fired on the next test.

One more lesson: a search on the manager for the word `TestPersist` matched my own `sudo grep` commands (they appear in the auth log and trigger rule 5402), which produced a misleading hit count. When a result looks too convenient, check what exactly it matched.

## Limitations and next steps

- **Noise.** Legitimate software (updaters, chat clients, sync tools) writes Run keys. Level 8 for every write would be too noisy in a real environment. Better logic would raise severity when the target binary lives in a user-writable path (AppData, Temp, Downloads), when the writer is a scripting host such as PowerShell or wscript, or when the write follows other suspicious activity.
- **Coverage.** The test used the current-user key (HKCU). Local-machine keys, `RunOnce`, the Startup folder, services and scheduled tasks were not tested, and the rule only covers the paths that rule 92300 covers.
- **Detection value of the parent.** Because the rule inherits from 92300, it only fires when 92300 matches, so any evasion of that pattern also evades this rule.
- Planned: test the HKLM and `RunOnce` variants, and add severity tuning based on the target path.
