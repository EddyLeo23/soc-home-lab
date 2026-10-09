#!/usr/bin/env python3
"""
Local LLM triage of saved Wazuh alerts, using Ollama (standard library only).

For each saved alert it asks the model for a structured verdict (severity, verdict,
reason, next step), then writes results.json and results.md next to this script.
The expected verdicts below come from my own write-ups and are never shown to the
model; they are only used to score its answers afterwards.

Run from anywhere:  python phase2-pipeline/ai-triage/ai_triage.py
Requires Ollama running locally with the model below already pulled.
"""
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:3b"

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]  # .../soc-home-lab

# Ground truth, labelled from the detection write-ups. The three technique tests are
# behaviours I ran on purpose, so a SOC should flag them. The agent-startup event is
# the Wazuh agent's own activity and should be closed as benign.
EXPECTED = {
    "T1087-account-discovery": "suspicious",
    "T1082-system-discovery": "suspicious",
    "T1547-registry-run-key": "suspicious",
    "T1087-agent-startup-alert": "benign",
}

PROMPT = (
    "You are a Tier 1 SOC analyst triaging a Wazuh alert from a Windows endpoint. "
    "Decide whether the activity is more likely benign or suspicious, using only the "
    "evidence in the alert. Reply with JSON only, using exactly these keys: "
    "severity (one of: low, medium, high), "
    "verdict (one of: benign, suspicious), "
    "reason (one or two sentences that cite specific fields from the alert), "
    "next_step (one short action).\n\nAlert:\n"
)


def load_samples():
    samples = []
    detections = REPO / "phase1-detection" / "detections"
    for path in sorted(detections.glob("*/alert-excerpt.json")):
        samples.append((path.parent.name, path))
    for path in sorted((HERE / "samples").glob("*.json")):
        samples.append((path.stem, path))
    return samples


def strip_notes(alert):
    # Drop helper keys such as "_note" so they cannot hint at the answer.
    return {k: v for k, v in alert.items() if not k.startswith("_")}


def ask_model(alert):
    body = json.dumps(
        {
            "model": MODEL,
            "prompt": PROMPT + json.dumps(alert, indent=2),
            "stream": False,
            "format": "json",
            "options": {"temperature": 0},
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        OLLAMA_URL, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        raw = json.loads(response.read().decode("utf-8"))["response"]
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    return raw, parsed


def cell(text):
    return str(text).replace("|", "/").replace("\n", " ").strip()


def main():
    samples = load_samples()
    if not samples:
        print("No alert files found. Run this from inside the soc-home-lab repo.")
        sys.exit(1)

    results = []
    for label, path in samples:
        alert = strip_notes(json.loads(path.read_text(encoding="utf-8")))
        print(f"Triaging {label} ...", flush=True)
        try:
            raw, parsed = ask_model(alert)
        except urllib.error.URLError as err:
            print(f"\nCould not reach Ollama at {OLLAMA_URL}: {err}")
            print("Make sure Ollama is running (open it from the Start menu) and try again.")
            sys.exit(1)

        verdict = str(parsed.get("verdict", "unparsed")).strip().lower()
        expected = EXPECTED.get(label, "unknown")
        results.append(
            {
                "alert": label,
                "rule_id": alert.get("rule", {}).get("id"),
                "model_severity": str(parsed.get("severity", "unparsed")).strip().lower(),
                "model_verdict": verdict,
                "expected_verdict": expected,
                "match": verdict == expected,
                "model_reason": parsed.get("reason", ""),
                "model_next_step": parsed.get("next_step", ""),
                "raw_response": raw,
            }
        )
        print(f"  model: {verdict} | expected: {expected}")

    (HERE / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")

    matched = sum(1 for r in results if r["match"])
    lines = [
        "# AI triage results",
        "",
        f"Model: `{MODEL}` via Ollama, temperature 0. {len(results)} saved alerts, so this is a",
        "small illustration of model behaviour, not a benchmark.",
        "",
        f"**Verdicts matching my own labels: {matched} of {len(results)}**",
        "",
        "| Alert | Rule | Model severity | Model verdict | Expected | Match | Model reasoning |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} |".format(
                cell(r["alert"]),
                cell(r["rule_id"]),
                cell(r["model_severity"]),
                cell(r["model_verdict"]),
                cell(r["expected_verdict"]),
                "yes" if r["match"] else "NO",
                cell(r["model_reason"]),
            )
        )
    lines += [
        "",
        "## My review",
        "",
        "(Add notes here: where the model was right or wrong, whether its reasoning cited the",
        "fields that actually matter, such as integrity level and working directory, and what",
        "that means for trusting this kind of output.)",
        "",
    ]
    (HERE / "results.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"\nMatched {matched} of {len(results)}. Wrote results.json and results.md in {HERE}")


if __name__ == "__main__":
    main()
