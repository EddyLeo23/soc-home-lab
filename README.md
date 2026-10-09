# Home SOC Lab: Wazuh + Sysmon detection engineering

Built by Edwin López | [LinkedIn](https://www.linkedin.com/in/edwin2390/)

A small home SOC built to practise the detection side of security operations: collect endpoint telemetry, see what the default ruleset catches, find the gaps, and close them with custom rules. Each detection is tested against a real endpoint and documented with the alert, the reasoning, and the limitations. A second part tests how far a small local language model can be trusted to triage the resulting alerts.

**Status:** Phase 1 (detection) complete. Phase 2 has started: the AI-assisted triage experiment is done, and case management, enrichment and automation are planned and not built yet.

## Architecture

```mermaid
flowchart LR
  A["Windows 11 endpoint<br/>Sysmon + Wazuh agent"] -->|Sysmon events| B["Wazuh manager<br/>Ubuntu 22.04 VM"]
  B --> C["Rules: default ruleset<br/>+ custom 100100, 100101"]
  C --> D["Wazuh dashboard<br/>alerts + MITRE mapping"]
  C -.->|saved alert excerpts| E["Local LLM triage experiment<br/>Ollama"]
```

| Component | Details |
|---|---|
| Manager | Wazuh 4.14.8 all-in-one (manager, indexer, dashboard) on Ubuntu 22.04 in VirtualBox (4 GB RAM, 2 vCPU, 50 GB disk) |
| Endpoint | Windows 11 laptop with Sysmon v15.22 (SwiftOnSecurity config) and the Wazuh 4.14.8 agent |
| Network | VirtualBox host-only network between laptop and VM |
| LLM triage | Ollama on the same laptop (`llama3.2:3b`, `gemma3:4b`), run with the VM switched off |

## Detections

| Technique | Behaviour tested | Detection | Rule | Level | Write-up |
|---|---|---|---|---|---|
| T1087 Account Discovery | `net user`, `net localgroup administrators` | Default ruleset | 92031 (plus 92033 for PowerShell origin) | 3 | [detections/T1087-account-discovery](phase1-detection/detections/T1087-account-discovery) |
| T1082 System Information Discovery | `systeminfo` | Custom rule (the default ruleset raised no alert) | 100100 | 6 | [detections/T1082-system-discovery](phase1-detection/detections/T1082-system-discovery) |
| T1547.001 Registry Run Keys | New value under the HKCU `Run` key | Custom rule, child of built-in rule 92300 | 100101 | 8 | [detections/T1547-registry-run-key](phase1-detection/detections/T1547-registry-run-key) |

The custom rules are in [phase1-detection/wazuh-manager](phase1-detection/wazuh-manager). Alert screenshots are in [screenshots](screenshots).

## AI-assisted triage experiment

I sent four saved alerts (the three detections above plus one benign Wazuh-agent event) to small local models and scored their verdicts against my own labels. Full write-up and results: [phase2-pipeline/ai-triage](phase2-pipeline/ai-triage).

| Run | Model | Prompt | Verdicts matching my labels |
|---|---|---|---|
| 1 | `llama3.2:3b` | basic | 1 of 4 |
| 2 | `llama3.2:3b` | guided | 1 of 4 |
| 3 | `gemma3:4b` | guided | 2 of 4 |

The smaller model called every alert benign, including a persistence entry. A better prompt changed how it wrote its answers but not its conclusions. The second model caught the persistence attempt but raised a false alarm on the benign event, for reasons that were wrong. Four alerts and one run per model make this an illustration, not a benchmark. The takeaway is to treat model output as a hypothesis to verify, not a verdict.

## What I learned

- **A default rule can match and still stay silent.** Wazuh's built-in rule 92300 recognises Run-key writes but is level 0, so it raises nothing. My first custom rule sat beside it and never fired. Making it a child of 92300 fixed it. The write-up shows how I ruled out Sysmon logging, delivery to the manager, and the pattern before finding that.
- **Check the gap before writing a rule.** For `systeminfo`, Sysmon logged the process but no default alert existed, so a custom rule was justified. For `net` commands, the default ruleset already covered it.
- **Triage the noise, don't assume.** The first discovery alert came from the Wazuh agent's own startup, not from my test. Integrity level and the working directory told them apart.
- **Validate before restarting.** Every rule change was backed up and tested with `wazuh-analysisd -t` before the manager restarted.
- **Disk sizing matters.** Ubuntu's installer used only about half of the 50 GB virtual disk for the root volume, and the Wazuh dashboard install failed with "No space left on device". Expanding the logical volume fixed it. VM snapshots at each milestone made recovery a one-minute rollback.
- **Tooling has limits.** `wazuh-logtest` cannot replay Windows event-channel events faithfully, so I tested rules against live events instead.
- **AI output needs verification.** Small models can sound confident while inventing details or dismissing a real persistence attempt. Reading the reasoning, not just counting matches, is what showed it.

## Limitations

- One endpoint, and it is my own laptop, not an isolated VM, because of an 8 GB RAM limit. Tests were limited to harmless read-only commands and a reversible registry value.
- Single Sysmon configuration, no baselining, and alert levels are starting points, not tuned values. See each write-up for false-positive notes and tuning ideas.
- The detections test one behaviour each. Variants and evasions (renamed binaries, other Run-key locations) are listed as next steps in the write-ups.
- The AI experiment is small: four alerts, two small models, labels set by me.

## Planned

Case management (TheHive), threat-intelligence enrichment (MISP) and automation (Shuffle). Not started; the 8 GB hardware limit means these would be built one at a time.

## Repository layout

```
phase1-detection/
  detections/        one folder per technique: write-up + trimmed alert
  wazuh-manager/     custom rules
  log.md             build log
phase2-pipeline/
  ai-triage/         local LLM triage experiment: script, samples, results
screenshots/         alert evidence
```
