# AI triage results: guided prompt, llama3.2:3b

Model `llama3.2:3b` via Ollama, temperature 0, prompt variant `guided`.
4 saved alerts, so this is a small illustration of model behaviour,
not a benchmark.

**Verdicts matching my own labels: 1 of 4**

| Alert | Rule | Model severity | Model verdict | Expected | Match | Model reasoning |
|---|---|---|---|---|---|---|
| T1082-system-discovery | 100100 | low | benign | suspicious | NO | The alert is triggered by systeminfo.exe, a built-in Windows tool, executed by a legitimate process (WindowsPowerShell) as a medium-integrity user (LAB-ENDPOINT\labuser). |
| T1087-account-discovery | 92031 | low | benign | suspicious | NO | The process 'net1.exe' is a built-in Windows tool, and the command line is a legitimate action to join a local group. The user running the process is 'labuser' with medium integrity level. |
| T1547-registry-run-key | 100101 | low | benign | suspicious | NO | The event is a legitimate autostart entry for the 'calc.exe' executable, which is a built-in Windows tool. The user running the event is 'labuser' with a valid Windows account. |
| T1087-agent-startup-alert | 92031 | low | benign | benign | yes | The process 'net1.exe' is a built-in Windows tool, and it is running with System integrity level, which is a normal and expected behavior. |

## My review

Run 2: `llama3.2:3b`, guided prompt. The guidance was written after seeing run 1's failures, so this comparison shows whether guidance helps, not how the model performs on unseen alerts.

- Verdicts did not change: all four benign, 1 of 4 matched.
- The reasoning style did change. The model now cites the user, the integrity level and, in one case, the parent process, as the prompt asks.
- Citing a field is not the same as using it. It still reasons from "built-in Windows tool" to benign on three alerts, which the prompt explicitly says not to do. On the Run-key alert it identified an autostart entry for `calc.exe` and still called it legitimate.
- It still invents details: `net localgroup administrators` is again described as an action to "join a local group".
- The one match (agent startup) cites the System integrity level, a relevant field, but the model said benign for everything, so this is not evidence that it discriminates between cases.
- Takeaway: for this small model, prompt guidance changed how the answers were written and not what they concluded. Run 3 keeps the guided prompt and changes only the model.
