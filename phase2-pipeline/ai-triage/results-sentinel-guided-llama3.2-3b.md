# AI triage results: guided prompt, llama3.2:3b

Model `llama3.2:3b` via Ollama, temperature 0, prompt variant `guided`.
5 saved alerts, so this is a small illustration of model behaviour,
not a benchmark.

**Verdicts matching my own labels: 3 of 5**

| Alert | Rule | Model severity | Model verdict | Expected | Match | Model reasoning |
|---|---|---|---|---|---|---|
| T1110-5-failed-logons | Repeated failed logons (T1110.001) | low | benign | suspicious | NO | Failed logon attempt from a legitimate user account (TargetAccount: labtest) with a known failure type (Wrong password (account exists)) |
| T1110-7-failed-logons | Repeated failed logons (T1110.001) | low | benign | suspicious | NO | Failed logon attempts are expected and logged by Windows, and the 'Repeated failed logons' rule is designed to detect this behavior. |
| T1547-atomic-run-key | Registry Run key persistence (T1547.001) | medium | suspicious | suspicious | yes | The use of reg.exe to write to a registry key is suspicious, as it could be used to persist, and the payload is a new executable (Atomic Red Team) that is not a built-in Windows tool. |
| T1547-edge-copilot-updater | Registry Run key persistence (T1547.001) | low | benign | benign | yes | The process 'setup.exe' is a legitimate installer for the Microsoft Copilot application, and the registry key modification is likely a necessary step for the application to function properly. |
| T1547-edge-webview-updater | Registry Run key persistence (T1547.001) | medium | benign | benign | yes | The process 'setup.exe' is a legitimate installer for Microsoft Edge, and the registry key persistence is likely a normal behavior for the application. |

## My review

(Add notes here: where the model was right or wrong, whether its reasoning cited the
fields that actually matter, and how this run differs from the earlier ones.)
