#!/usr/bin/env python3
"""
Local LLM triage of saved Wazuh alerts, using Ollama (standard library only).

For each saved alert it asks the model for a structured verdict (severity, verdict,
reason, next step), then writes results-<variant>-<model>.json and .md next to this
script. Each run is labelled by prompt variant and model, and existing result files
are never overwritten, so runs can be compared side by side.

The expected verdicts below come from my own write-ups and are never shown to the
model; they are only used to score its answers afterwards.

Usage (from anywhere):
  python phase2-pipeline/ai-triage/ai_triage.py --variant basic
  python phase2-pipeline/ai-triage/ai_triage.py --variant guided
  python phase2-pipeline/ai-triage/ai_triage.py --variant guided --model gemma3:4b

Requires Ollama running locally with the chosen model already pulled.
"""
import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2:3b"

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

REPLY_FORMAT = (
    "Reply with JSON only, using exactly these keys: "
    "severity (one of: low, medium, high), "
    "verdict (one of: benign, suspicious), "
    "reason (one or two sentences that cite specific fields from the alert), "
    "next_step (one short action).\n\nAlert:\n"
)

# Run 1: the original prompt, kept unchanged so that run can be reproduced.
PROMPT_BASIC = (
    "You are a Tier 1 SOC analyst triaging a Wazuh alert from a Windows endpoint. "
    "Decide whether the activity is more likely benign or suspicious, using only the "
    "evidence in the alert. " + REPLY_FORMAT
)

# Run 2: general analyst guidance added after seeing run 1's failures. It describes what
# to examine, not what the answer is, but it was written with knowledge of run 1, so the
# comparison is an illustration and not a clean benchmark.
PROMPT_GUIDED = (
    "You are a Tier 1 SOC analyst triaging a Wazuh alert from a Windows endpoint. "
    "Decide whether the activity is more likely benign or suspicious, using only the "
    "evidence in the alert.\n\n"
    "Guidance:\n"
    "- Wazuh and Sysmon are sensors that record activity. They are never the actor. "
    "The actor is the process in 'image' and 'commandLine', started by 'parentImage', "
    "running as 'user' at the stated 'integrityLevel' from 'currentDirectory'.\n"
    "- A tool being built into Windows does not make its use benign. Attackers often use "
    "built-in tools, so judge the context: who ran it, from which parent process, at what "
    "integrity level, from which directory, and what value or target is involved.\n"
    "- Do not describe what a command does unless you are sure. If you are unsure, say so.\n"
    "- Some behaviours (autostart entries, new accounts, scheduled tasks, service creation) "
    "establish persistence. For those, consider which program is launched and which "
    "process created the entry.\n"
    "- Base severity on how risky the behaviour is in context, not on how common the tool is.\n\n"
    + REPLY_FORMAT
)

VARIANTS = {"basic": PROMPT_BASIC, "guided": PROMPT_GUIDED}


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


def ask_model(model, prompt, alert):
    body = json.dumps(
        {
            "model": model,
            "prompt": prompt + json.dumps(alert, indent=2),
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
    parser = argparse.ArgumentParser(description="Triage saved Wazuh alerts with a local LLM.")
    parser.add_argument("--variant", choices=sorted(VARIANTS), required=True,
                        help="which prompt to use")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    args = parser.parse_args()

    slug = args.model.replace(":", "-").replace("/", "-")
    out_json = HERE / f"results-{args.variant}-{slug}.json"
    out_md = HERE / f"results-{args.variant}-{slug}.md"
    if out_json.exists() or out_md.exists():
        print(f"Results for this variant and model already exist ({out_md.name}).")
        print("Not overwriting. Rename or move the old files first if you really want to re-run.")
        sys.exit(1)

    samples = load_samples()
    if not samples:
        print("No alert files found. Run this from inside the soc-home-lab repo.")
        sys.exit(1)

    prompt = VARIANTS[args.variant]
    results = []
    for label, path in samples:
        alert = strip_notes(json.loads(path.read_text(encoding="utf-8")))
        print(f"Triaging {label} ...", flush=True)
        try:
            raw, parsed = ask_model(args.model, prompt, alert)
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

    out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")

    matched = sum(1 for r in results if r["match"])
    lines = [
        f"# AI triage results: {args.variant} prompt, {args.model}",
        "",
        f"Model `{args.model}` via Ollama, temperature 0, prompt variant `{args.variant}`.",
        f"{len(results)} saved alerts, so this is a small illustration of model behaviour,",
        "not a benchmark.",
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
        "fields that actually matter, and how this run differs from the earlier ones.)",
        "",
    ]
    out_md.write_text("\n".join(lines), encoding="utf-8")

    print(f"\nMatched {matched} of {len(results)}. Wrote {out_md.name} and {out_json.name} in {HERE}")


if __name__ == "__main__":
    main()
