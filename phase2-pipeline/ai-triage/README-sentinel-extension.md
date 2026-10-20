# AI-assisted triage of Microsoft Sentinel alerts (Phase 3 extension)

## Overview

This experiment runs two locally hosted language models on five Microsoft Sentinel alerts, extending the earlier [Wazuh-based experiment](README.md). It uses `ai_triage_sentinel.py`, a Sentinel-specific adaptation of `ai_triage.py`: an edited copy with different labels, input folder and results prefix. The prompts are unchanged.

The aim is to see whether a small local model can help prioritise alerts, and to find where its verdicts or explanations fail. This is a small exploratory test, not a benchmark.

**Key finding:** in this test, neither model's verdicts could stand as an independent verdict. The two models failed in opposite directions, and one cited evidence that the alert did not contain.

## Method and labels

- **Alerts (5):** reconstructed from the custom details and entities of Sentinel incidents, not raw exports: two bursts of failed logons (5 and 7) that I generated against a test account in a controlled lab, a Run-key write by Atomic Red Team test 1, and two Run-key writes by real Microsoft Edge updaters (Copilot and EdgeWebView installers running as SYSTEM).
- **Reference labels:** the failed-logon bursts and the Atomic write are suspicious (I produced them); the two updater writes are benign (real updates). These are my own assessment from what I ran and observed, not independently validated. They were recorded in the build log in commit `425c480` (2026-10-20 14:20, with the samples), written into the script's `EXPECTED` table in `6c2782b` (14:26), and the results were committed in `778572b` (14:41), so the runs took place between the last two. Times come from the committing computer's clock (+0200) and show the order of the commits, not when I chose the labels. A small script fix (argument description, check for unlabelled samples) followed in `f188f06` (15:17), after the runs.
- **Reconstruction details:** the key names in the samples (for example `TargetAccount`) are mine. For the Atomic alert I replaced my username with the placeholder `Account: "user session"`. That is not a Sentinel value, and two of the three runs quoted it in their reasoning. The Atomic alert is also an easy case: its value name and payload say "Atomic Red Team".
- **Left out:** two incidents that carried my email and public IP.
- **Prompts:** `basic` and `guided`, unchanged from the Wazuh experiment, including the "Wazuh alert" wording and the Sysmon field names (`integrityLevel`, `currentDirectory`, `parentImage`), which these alerts do not carry.

| Run | Model (ID from `ollama list`) | Prompt |
|---|---|---|
| 1 | `gemma3:4b` (68ceab7e468a) | guided |
| 2 | `llama3.2:3b` (a80c4f17acd5) | guided |
| 3 | `llama3.2:3b` (a80c4f17acd5) | basic |

All runs: temperature 0, 2026-10-20, through Ollama on a local machine.

## Reconstruction details

The five samples are rebuilt from what the Sentinel incident pages showed, not from raw events. The wrapper (`source`, `host`, `rule`, `severity`, `description`, `fields`) is my structure, and the `note` key is removed by the script before the model sees the alert. None of the samples carries a time, so a model cannot judge how fast the failures happened.

| Sample | Incident | Taken from the incident | Written or changed by me | Not included |
|---|---|---|---|---|
| 5 failed logons | 15 | rule name, severity, FailedCount, LogonProcesses, FailureTypes, account name | description sentence (the alert text with its brackets removed); key name `TargetAccount`; `LogonTypes: [2]`, which I assumed (seen in the query results of incident 9, not checked for 15) | first and last failure times, source address, incident title |
| 7 failed logons | 9 | the same, with FailedCount 7 and LogonTypes [2] seen in the query results | description sentence; key name `TargetAccount` | the same |
| Atomic Run-key write | 8 | rule name, severity, ValueName, Payload, Process | description sentence in my own wording (the real alert text is "{ValueName} set to {Details} by {Image} in a Run/RunOnce key."); `Account: "user session"`, a placeholder for my username that is not a Sentinel value; key name `Account` | write time, user name |
| Edge Copilot updater write | 6 | rule name, severity, ValueName, Payload, Process, account SYSTEM | description sentence in my own wording; key name `Account` | write time |
| Edge WebView updater write | 11 | the same as the Copilot sample | description sentence in my own wording; key name `Account` | write time |

## Results

| Run | Matches with my labels | Suspicious alerts missed (of 3) | Benign alerts flagged as suspicious (of 2) |
|---|---|---|---|
| 1 | 3 of 5 | 0 | 2 |
| 2 | 3 of 5 | 2 | 0 |
| 3 | 2 of 5 | 3 | 0 |

The two 3-of-5 scores hide opposite failure patterns.

| Alert | Expected | Run 1 | Run 2 | Run 3 |
|---|---|---|---|---|
| 5 failed logons | suspicious | suspicious | benign | benign |
| 7 failed logons | suspicious | suspicious | benign | benign |
| Atomic Run-key write | suspicious | suspicious | suspicious | benign |
| Edge Copilot updater write | benign | suspicious | benign | benign |
| Edge WebView updater write | benign | suspicious | benign | benign |

## Error analysis

- **Opposite directions.** `gemma3:4b` classified all five alerts as suspicious: it caught every attack-like alert and flagged both real updates. `llama3.2:3b` missed suspicious activity: with the guided prompt it called both failed-logon bursts benign, and with the basic prompt it called all five benign. A missed attack is generally the costlier error, but a flood of false alarms is a real cost too, and the Sentinel rule itself already alerts on these Edge updates.
- **Unsupported evidence.** `gemma3:4b` called the Copilot updater suspicious partly because of "a high integrity level". The alert has no integrity level. The guided prompt tells the model to check `integrityLevel`, a Sysmon field, and these alerts do not carry it. A prompt written for one data source can push a model to fabricate evidence when the alerts come from another.
- **Misreading real fields.** With the guided prompt, `llama3.2:3b` read "Wrong password" as reassuring and did not use the count of 5. With the basic prompt it treated the alert's rule as proof of a legitimate security measure and described the `reg.exe` write as "related to a scheduled task".
- **Guidance changed one verdict** for `llama3.2:3b`: the Atomic write, from benign to suspicious. It did not fix the failed-logon alerts.

### Evidence audit (my reading of 9 of the 15 explanations)

I read the explanations for the 5-failed-logons, Atomic and Copilot alerts in each run. I did not read the other six, and this audit is my own, not independently checked.

| Run | Alert | Cited real fields | Misread or invented |
|---|---|---|---|
| 1 | 5 failed logons | count, failure type, account, `seclogo` | called it brute force or credential stuffing; the alert shows one account |
| 1 | Atomic write | `reg.exe`, value, payload | quoted my "user session" placeholder |
| 1 | Copilot updater | SYSTEM, `--system-level`, `--delete-old-versions` | invented an integrity level; read a cleanup flag as data manipulation |
| 2 | 5 failed logons | account, failure type | read "Wrong password" as reassuring; ignored the count |
| 2 | Atomic write | `reg.exe`, new executable payload | none seen |
| 2 | Copilot updater | legitimate installer | none seen |
| 3 | 5 failed logons | failure type | treated the rule as a legitimate security measure; called it a one-time mistake |
| 3 | Atomic write | `reg.exe` | invented a scheduled task; quoted the placeholder; said the payload was "not explicitly malicious" |
| 3 | Copilot updater | `setup.exe`, SYSTEM | none seen |

## Limitations and threats to validity

- Five alerts, one run per configuration, 15 verdicts. The two failed-logon alerts are nearly the same alert, so the five are not independent.
- The labels are mine, and I produced three of the five events.
- The alerts are reconstructions with placeholder values, and the prompts were written for Wazuh and Sysmon fields these alerts do not carry. I did not change the prompt after seeing the results.
- The guided prompt was written after the Wazuh experiment's first run showed failures, as noted in its README.
- Two small models only, at temperature 0, so repeats would probably reproduce the same output. Not tested.
- All 15 responses parsed, but the script does not validate permitted values, so a malformed answer would be counted as a mismatch and not reported as invalid.
- The alert text was passed to the model as-is. Instruction-like text inside an alert was not tested.

## Next experiment

- A Sentinel-specific prompt variant, written and committed before it runs, as a new named variant. It would list the fields these alerts actually carry, ask the model to name the input field behind each claim, and to report missing data as "not available". It runs on the same five samples first, then on a larger and more varied set (including ambiguous cases and role-assignment alerts with placeholder values).
- Complete the model-by-prompt grid: `gemma3:4b` with the basic prompt.
- Add output validation (required keys, permitted values, non-empty reasoning), and an audit of the six unread explanations.
- Keep every existing result unchanged so the experiment stays auditable. Any later use would be analyst-visible enrichment only, never an automatic decision.

## Files

- `ai_triage_sentinel.py`: the script. Usage: `python phase2-pipeline/ai-triage/ai_triage_sentinel.py --variant guided --model gemma3:4b`. It refuses to overwrite earlier results.
- `results-sentinel-guided-gemma3-4b.md` / `.json`: run 1.
- `results-sentinel-guided-llama3.2-3b.md` / `.json`: run 2.
- `results-sentinel-basic-llama3.2-3b.md` / `.json`: run 3.
- `samples-sentinel/`: the five reconstructed alerts (the labels are in the script, not in these files).

