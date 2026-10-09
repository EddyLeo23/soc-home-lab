# AI triage results: guided prompt, gemma3:4b

Model `gemma3:4b` via Ollama, temperature 0, prompt variant `guided`.
4 saved alerts, so this is a small illustration of model behaviour,
not a benchmark.

**Verdicts matching my own labels: 2 of 4**

| Alert | Rule | Model severity | Model verdict | Expected | Match | Model reasoning |
|---|---|---|---|---|---|---|
| T1082-system-discovery | 100100 | low | benign | suspicious | NO | The alert indicates `systeminfo.exe` was executed by `powershell.exe` at a medium integrity level, which is a standard tool for gathering system information. While it's a potential indicator of compromise, the context of execution by PowerShell and the medium integrity level suggest it's likely a routine system check. |
| T1087-account-discovery | 92031 | medium | suspicious | suspicious | yes | The alert indicates `net1.exe` is being used to query for membership in the 'administrators' group, which is a common tactic for reconnaissance. The parent process is `net.exe`, and the user is running with Medium integrity level, suggesting potential unauthorized access attempts. |
| T1547-registry-run-key | 100101 | medium | suspicious | suspicious | yes | The alert indicates a 'Run' key in the registry was set to 'calc.exe' using PowerShell, which is a built-in Windows application. While not inherently malicious, the use of a 'Run' key for persistence is a common tactic used by attackers to maintain access. |
| T1087-agent-startup-alert | 92031 | medium | suspicious | benign | NO | The alert indicates `net1.exe` is being run with `net user` from a suspicious directory (`C:\Program Files (x86)\ossec-agent\`) and at the 'System' integrity level, which suggests potential reconnaissance activity.  The parent process `net.exe` also running `net user` further raises suspicion. |

## My review

Run 3: `gemma3:4b`, same guided prompt as run 2. Only the model changed.

- 2 of 4 verdicts matched. Unlike the first two runs, this model did not call everything benign: it flagged `net localgroup administrators` and the Run-key write as suspicious.
- The two correct calls had mostly sound reasoning. It described `net1.exe` as querying membership of the administrators group (`llama3.2:3b` said "join"), and it identified a Run key set to `calc.exe` through PowerShell as a persistence technique, with an appropriate hedge ("not inherently malicious").
- It misjudged the benign agent-startup event as suspicious. It called `C:\Program Files (x86)\ossec-agent\` a "suspicious directory" (it is a normal install location) and read the System integrity level and the `net.exe` parent as reasons for suspicion. The facts that actually explain the event were treated as evidence against it. `net.exe` launching `net1.exe` is simply how the `net` command works.
- It called `systeminfo` benign, noting the medium integrity level and PowerShell context. My expected label for this alert is debatable: the T1082 write-up itself notes that administrators run `systeminfo` legitimately, so a lone run is low-value on its own. I did not change the label after seeing the result.
- The error types differ between models: `llama3.2:3b` produced false negatives (missed persistence), `gemma3:4b` produced one false positive and one arguable miss. In a SOC, a missed attack is generally the costlier error, while a false positive costs analyst time.
- Caveat: four alerts, one run per model, temperature 0. This illustrates model behaviour and is not a benchmark.
