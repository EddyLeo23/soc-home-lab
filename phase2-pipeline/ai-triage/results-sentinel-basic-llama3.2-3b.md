# AI triage results: basic prompt, llama3.2:3b

Model `llama3.2:3b` via Ollama, temperature 0, prompt variant `basic`.
5 saved alerts, so this is a small illustration of model behaviour,
not a benchmark.

**Verdicts matching my own labels: 2 of 5**

| Alert | Rule | Model severity | Model verdict | Expected | Match | Model reasoning |
|---|---|---|---|---|---|---|
| T1110-5-failed-logons | Repeated failed logons (T1110.001) | medium | benign | suspicious | NO | The alert is triggered by a scheduled analytics rule, indicating a legitimate security measure. The failure type is 'Wrong password (account exists)', which suggests a user attempting to log in with an incorrect password. |
| T1110-7-failed-logons | Repeated failed logons (T1110.001) | medium | benign | suspicious | NO | The alert is triggered by a scheduled analytics rule, indicating a legitimate security measure. The failure type is 'Wrong password (account exists)', which suggests a user attempting to log in with an incorrect password. |
| T1547-atomic-run-key | Registry Run key persistence (T1547.001) | medium | benign | suspicious | NO | The activity is related to a scheduled task (reg.exe) and a legitimate process (user session), which suggests a benign activity. The specific payload (Atomic Red Team) is not explicitly mentioned as being malicious. |
| T1547-edge-copilot-updater | Registry Run key persistence (T1547.001) | medium | benign | benign | yes | The activity is likely benign as it involves a legitimate registry key persistence by a system process (setup.exe) and the payload is a standard installer command. The use of NT AUTHORITY\SYSTEM as the account also suggests a system-level operation. |
| T1547-edge-webview-updater | Registry Run key persistence (T1547.001) | medium | benign | benign | yes | The activity is likely benign as it involves the installation of Microsoft Edge, a legitimate application, and the 'delete-old-versions' flag is often used to remove outdated versions of the application. |

## My review

(Add notes here: where the model was right or wrong, whether its reasoning cited the
fields that actually matter, and how this run differs from the earlier ones.)
