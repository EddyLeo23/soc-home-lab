# AI triage results

Model: `llama3.2:3b` via Ollama, temperature 0. 4 saved alerts, so this is a
small illustration of model behaviour, not a benchmark.

**Verdicts matching my own labels: 1 of 4**

| Alert | Rule | Model severity | Model verdict | Expected | Match | Model reasoning |
|---|---|---|---|---|---|---|
| T1082-system-discovery | 100100 | low | benign | suspicious | NO | The event is a normal system information discovery event triggered by the systeminfo.exe executable, which is a built-in Windows utility. The event is logged by Sysmon, a monitoring tool that tracks system activity. |
| T1087-account-discovery | 92031 | low | benign | suspicious | NO | The event is a discovery activity executed by the sysmon agent, which is a normal and expected activity. The event is related to the 'Account Discovery' technique, but the specific action is a legitimate system call to join a local group. |
| T1547-registry-run-key | 100101 | low | benign | suspicious | NO | The event is a legitimate system event from the Windows Sysmon agent, indicating a scheduled task was run. The target object is a legitimate registry key. |
| T1087-agent-startup-alert | 92031 | low | benign | benign | yes | The event is a normal Windows event (Event ID 1) executed by the Sysmon agent, indicating a discovery activity. |

## My review

Run 1: `llama3.2:3b`, basic prompt with no guidance on which fields to examine.

- The model called all four alerts benign, including PowerShell writing an autostart Run-key entry for `calc.exe`. In a real SOC that is a missed persistence attempt.
- Its one match (the agent-startup event) is not evidence of skill: it said benign for everything, and its reasoning cited neither the System integrity level nor the `ossec-agent` working directory that actually explain that event.
- It treated Sysmon, the logging sensor, as the actor ("executed by the Sysmon agent").
- It reasoned from "built-in Windows utility" to "benign", and never mentioned the user, integrity level, parent process or the value written to the registry.
- It invented details: `net localgroup administrators` became a call "to join a local group", and the Run-key write became "a scheduled task was run".
- It rated every alert low severity, including the one raised by a level-8 rule.
- Caveat: one small model, one prompt and four alerts, so this illustrates model behaviour and is not a benchmark.
