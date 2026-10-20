# AI triage on Sentinel alerts (Phase 3 extension)

The same experiment as the Wazuh one described in [README.md](README.md), run on five alerts from Microsoft Sentinel with `ai_triage_sentinel.py`, an edited copy of `ai_triage.py`. It has different labels, a different input folder (`samples-sentinel/`) and a different results prefix. The prompts are unchanged, including the "Wazuh alert" wording and the Sysmon field names.

## Setup

- **Alerts (5):** reconstructed from the custom details of Sentinel incidents, not raw exports: two bursts of failed logons (5 and 7) against a test account I attacked on purpose, a Run-key write by Atomic Red Team test 1, and two Run-key writes by real Microsoft Edge updaters (Copilot and EdgeWebView installers running as SYSTEM).
- **Labels, fixed before any run:** failed-logon bursts and the Atomic write are suspicious (I produced them); the two updater writes are benign (real updates). The samples and labels were committed first (`425c480`), then the script (`6c2782b`), then the results.
- **Easy case:** the Atomic alert says "Atomic Red Team" in the value name and payload, so a correct verdict on it is weak evidence.
- **Left out:** two incidents that carried my email and public IP.

## Results

| Run | Model | Prompt | Verdicts matching my labels |
|---|---|---|---|
| 1 | `gemma3:4b` | guided | 3 of 5 |
| 2 | `llama3.2:3b` | guided | 3 of 5 |
| 3 | `llama3.2:3b` | basic | 2 of 5 |

| Alert | Expected | Run 1 | Run 2 | Run 3 |
|---|---|---|---|---|
| 5 failed logons | suspicious | suspicious | benign | benign |
| 7 failed logons | suspicious | suspicious | benign | benign |
| Atomic Run-key write | suspicious | suspicious | suspicious | benign |
| Edge Copilot updater write | benign | suspicious | benign | benign |
| Edge WebView updater write | benign | suspicious | benign | benign |

## What I found

I read the model reasoning for three of the five alerts in each run (5 failed logons, the Atomic write and the Copilot updater); the other two alerts' reasoning is in the results files and I did not read it.

- **The two models failed in opposite directions again.** `gemma3:4b` flagged everything, so it caught every attack-like alert and called both real updater writes suspicious. `llama3.2:3b` under-flagged: with the guided prompt it called both failed-logon bursts benign, and with the basic prompt it called all five benign. A missed attack is generally the costlier error, but a flood of false positives is a real cost too, and the Sentinel rule itself already alerts on these Edge updates.
- **The model invented a field.** `gemma3:4b` called the Copilot updater suspicious partly because it ran "at a high integrity level". The alert has no integrity level. The guided prompt tells the model to check `integrityLevel`, a Sysmon field, and these alerts do not carry it. A prompt written for one data source can push a model to fabricate evidence when the alerts come from another.
- **The 3 of 5 scores hide different reasoning.** Both guided runs scored 3 of 5, with different mistakes. `llama3.2:3b` read "Wrong password" as reassuring and described the 5-failure burst as a user making a mistake.
- **Small models invent details.** With the basic prompt, `llama3.2:3b` described the `reg.exe` write as "related to a scheduled task" and said the payload "Atomic Red Team" was not explicitly malicious.
- **Guidance changed one verdict for `llama3.2:3b`:** the Atomic write, from benign to suspicious. It did not fix the failed-logon alerts.

**Takeaway:** the result repeats the Wazuh experiment. Treat model output as a hypothesis to check against the alert fields, not as a verdict, and be most suspicious of a confident "benign".

## Limitations

- Five alerts and one run per configuration: an illustration, not a benchmark. The two failed-logon alerts are nearly the same alert, so the five are not independent.
- Labels are my own judgement, and I also produced three of the five events.
- The alerts are reconstructions of the incident custom details, and the prompts were written for Wazuh and Sysmon fields (`integrityLevel`, `currentDirectory`, `parentImage`) that these alerts do not have. I did not change the prompt after seeing the results.
- The guided prompt was written after the Wazuh experiment's run 1 failures, as noted in its README.
- Two small models only.

## Possible next steps

- A prompt variant written for Sentinel fields, run as a new named variant next to these, so the Wazuh-field mismatch can be measured.
- More benign alerts, so a false-positive rate can be measured, and hosted or larger models.

## Files

- `ai_triage_sentinel.py`: the script. Usage: `python phase2-pipeline/ai-triage/ai_triage_sentinel.py --variant guided --model gemma3:4b`. It refuses to overwrite earlier results.
- `results-sentinel-guided-gemma3-4b.md` / `.json`: run 1.
- `results-sentinel-guided-llama3.2-3b.md` / `.json`: run 2.
- `results-sentinel-basic-llama3.2-3b.md` / `.json`: run 3.
- `samples-sentinel/`: the five reconstructed alerts (labels are in the script, not in these files).
