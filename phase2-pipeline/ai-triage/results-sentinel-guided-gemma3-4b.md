# AI triage results: guided prompt, gemma3:4b

Model `gemma3:4b` via Ollama, temperature 0, prompt variant `guided`.
5 saved alerts, so this is a small illustration of model behaviour,
not a benchmark.

**Verdicts matching my own labels: 3 of 5**

| Alert | Rule | Model severity | Model verdict | Expected | Match | Model reasoning |
|---|---|---|---|---|---|---|
| T1110-5-failed-logons | Repeated failed logons (T1110.001) | medium | suspicious | suspicious | yes | Multiple failed logons (5) with the 'Wrong password (account exists)' failure type targeting the 'labtest' account within a short timeframe suggests a brute-force attack or credential stuffing attempt. The use of 'seclogo' further indicates a login attempt. |
| T1110-7-failed-logons | Repeated failed logons (T1110.001) | medium | suspicious | suspicious | yes | Multiple failed logons with the 'Wrong password (account exists)' failure type, targeting the 'labtest' account, suggests a potential brute-force attack or credential stuffing attempt. The repeated nature of the failures elevates concern. |
| T1547-atomic-run-key | Registry Run key persistence (T1547.001) | medium | suspicious | suspicious | yes | The alert indicates `reg.exe` wrote a value ('Atomic Red Team') pointing to an executable (`AtomicRedTeam.exe`) from a potentially unusual location, and the account is a 'user session'. This suggests a possible persistence mechanism, particularly if the executable is associated with malicious activity. |
| T1547-edge-copilot-updater | Registry Run key persistence (T1547.001) | medium | suspicious | benign | NO | The alert indicates `setup.exe` (Microsoft Copilot Installer) is writing to the registry via `NT AUTHORITY\SYSTEM` with a high integrity level, and the payload includes `--system-level` and `--delete-old-versions` flags, suggesting potential persistence and data manipulation. |
| T1547-edge-webview-updater | Registry Run key persistence (T1547.001) | medium | suspicious | benign | NO | The alert indicates `setup.exe` (a legitimate Windows installer) is writing to the registry and using the `--delete-old-versions` flag, which is often associated with malicious cleanup activities. The use of `--system-level` and `--verbose-logging` further raises suspicion, as these options are frequently employed by malware to avoid detection. |

## My review

(Add notes here: where the model was right or wrong, whether its reasoning cited the
fields that actually matter, and how this run differs from the earlier ones.)
