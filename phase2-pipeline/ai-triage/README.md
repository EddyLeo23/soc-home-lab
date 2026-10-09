# AI-assisted alert triage with a local LLM

An experiment in how far a small local language model can be trusted to triage Wazuh alerts. The script `ai_triage.py` sends saved alert excerpts to a model running locally through Ollama and asks for a structured verdict (severity, benign or suspicious, a reason, a next step). I then score the answers against my own labels and read the reasoning, because the reasoning matters more than the score.

## Setup

- **Alerts (4):** the three detections from Phase 1 (T1087, T1082, T1547.001), which I ran on purpose, plus one benign alert: the Wazuh agent's own `net user` call at startup. The benign sample is reconstructed from the fields I saw in the dashboard, not a raw export, and is labelled as such in its file.
- **Labels:** the three technique tests are expected to be flagged as suspicious, and the agent-startup event as benign. The labels live in the script, come from my own write-ups, and are never shown to the model.
- **Model output:** JSON with `severity`, `verdict`, `reason` and `next_step`. Temperature 0.
- **Hardware:** an 8 GB RAM laptop with the Wazuh VM switched off while the model runs.

## Results

| Run | Model | Prompt | Verdicts matching my labels |
|---|---|---|---|
| 1 | `llama3.2:3b` | basic | 1 of 4 |
| 2 | `llama3.2:3b` | guided | 1 of 4 |
| 3 | `gemma3:4b` | guided | 2 of 4 |

Per alert:

| Alert | Expected | Run 1 | Run 2 | Run 3 |
|---|---|---|---|---|
| T1082 `systeminfo` | suspicious | benign | benign | benign |
| T1087 `net localgroup administrators` | suspicious | benign | benign | suspicious |
| T1547.001 Run-key write for `calc.exe` | suspicious | benign | benign | suspicious |
| Agent startup `net user` | benign | benign | benign | suspicious |

Full model reasoning for each run is in the results files listed at the end.

## What I found

- **Guidance changed how the small model wrote, not what it concluded.** After I added analyst guidance (sensors are not actors, built-in tools are not automatically benign, check user, parent, integrity level and directory), `llama3.2:3b` started citing those fields but still called all four alerts benign. It reasoned from "built-in Windows tool" to benign, the exact step the prompt warns against.
- **Citing a field is not using it.** In run 2 the model identified an autostart entry for `calc.exe` and still called it legitimate.
- **A different model changed the behaviour.** `gemma3:4b` flagged the group enumeration and the Run-key write, described `net1.exe` accurately, and recognised the Run key as a persistence technique with an appropriate hedge.
- **The error types differ.** `llama3.2:3b` made false negatives, missing the persistence attempt. `gemma3:4b` made a false positive on the agent event, calling a normal install directory "suspicious" and treating the System integrity level and the `net.exe` parent as warning signs. Those are the facts that explain the event. A missed attack is generally the costlier error, but a stream of false positives is a real cost too.
- **Smaller models invent details.** `llama3.2:3b` described `net localgroup administrators` as a call to join a group, and the Run-key write as a scheduled task.
- **One label is debatable.** I expected `systeminfo` to be flagged, but my own T1082 write-up notes that administrators run it legitimately, so calling a lone run low-risk is defensible. I did not change the label after seeing the results.

**Takeaway:** treat model output as a hypothesis to verify against the alert fields, not as a verdict. It can be a useful second opinion, but a human has to check its reasoning, especially when it says "benign".

## Limitations

- Four alerts, one run per model, so this illustrates behaviour and is not a benchmark.
- The guided prompt was written after seeing run 1's failures, so the run 1 versus run 2 comparison shows whether guidance helps, not how the model performs on unseen alerts.
- Labels are my own judgement.
- Two small models only. Larger or hosted models were not tested, and may behave quite differently.

## Possible next steps

- A larger labelled set, including more benign alerts, so the false-positive rate can be measured.
- Few-shot examples in the prompt, and a model with more capacity.
- Feeding the model derived facts (for example, whether the process runs from the Wazuh agent's own folder) and checking whether it uses them.

## Files

- `ai_triage.py`: the script. Usage: `python phase2-pipeline/ai-triage/ai_triage.py --variant guided --model gemma3:4b` (variants: `basic`, `guided`). It refuses to overwrite earlier results.
- `results-run1-basic-prompt.md` / `.json`: run 1.
- `results-guided-llama3.2-3b.md` / `.json`: run 2.
- `results-guided-gemma3-4b.md` / `.json`: run 3.
- `samples/`: the reconstructed benign alert.
