# Detection: Account / Group Discovery via `net` commands

| | |
|---|---|
| **MITRE ATT&CK** | T1087 Account Discovery (as mapped by Wazuh); tactic: Discovery |
| **Related technique** | `net localgroup` also aligns with T1069.001 Permission Groups Discovery: Local Groups |
| **Data source** | Sysmon Event ID 1 (process creation), SwiftOnSecurity config |
| **Wazuh rule** | 92031, level 3, "Discovery activity executed" |
| **Endpoint** | Windows 11 laptop, Wazuh agent 4.14.8 |
| **Manager** | Wazuh 4.14.8 all-in-one on Ubuntu 22.04 (VirtualBox) |
| **Date tested** | 2026-10-08 |

## What I did

In a regular (non-admin) PowerShell window on the endpoint I ran read-only enumeration commands:

```powershell
net user
net localgroup administrators
```

## What fired

Sysmon logged the process creation and Wazuh's default ruleset raised rule 92031 for `net1.exe localgroup administrators`. The event shows the command line, the user, the integrity level (Medium) and the parent process. A trimmed copy of the alert is in `alert-excerpt.json`.

## Triage: telling my test apart from background noise

The same rule had already fired earlier, at agent startup, before I ran anything. I did not assume it was mine, so I compared the two events:

| Field | Agent startup event | My test event |
|---|---|---|
| Command line | `net user` | `net localgroup administrators` |
| Integrity level | System | Medium |
| Current directory | `C:\Program Files (x86)\ossec-agent\` | `C:\WINDOWS\system32\` |
| Parent image | `net.exe` | `net.exe` |

The parent is the same in both cases because `net.exe` launches `net1.exe` itself, so the parent process does not separate them. Integrity level, the account, and the working directory do.

**Verdict:** the startup event is a benign false positive (the Wazuh agent enumerating the local system when it starts). My test event is a true positive for the behaviour being detected.

## Limitations and next steps

- Rule 92031 is level 3, so on its own it would not page anyone. In a real SOC I would correlate repeated discovery commands from one user in a short window, or the same commands arriving from an unusual parent such as a script host or an Office process.
- The agent's own startup `net user` shows how a default rule can generate noise. A tuning step would exclude that specific pattern (System integrity, `ossec-agent` working directory).
- Planned: a custom Wazuh rule for this activity, and separate testing of `systeminfo` (T1082).

## Update: second rule fired

Each test command also triggered rule 92033, "Discovery activity spawned via powershell execution", which confirms Wazuh links these commands to PowerShell as the originating shell.
