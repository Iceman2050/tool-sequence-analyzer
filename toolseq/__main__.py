"""CLI: python -m toolseq --log activity.jsonl [--tools tools.yaml] [--out report.md]"""
import argparse
import json
import os
import sys

from .analyzer import analyze, chain_to_mermaid, load_events, load_tool_map

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TOOLS = os.path.join(os.path.dirname(HERE), "default_tools.yaml")


def build_parser():
    p = argparse.ArgumentParser(
        description="Detect privilege-escalation patterns across agent tool-call sequences."
    )
    p.add_argument("--log", required=True, help="JSONL log, one JSON object per line")
    p.add_argument("--tools", default=DEFAULT_TOOLS, help="tools.yaml privilege map")
    p.add_argument("--out", default="report.md", help="Markdown report to write")
    p.add_argument("--window", type=int, default=6, help="lookahead window (events)")
    p.add_argument("--json", default=None, help="optional path to write findings as JSON")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    mapping, default_level = load_tool_map(args.tools)
    events = load_events(args.log)
    chains = analyze(events, mapping, default_level, window=args.window)

    lines = [
        "# tool-sequence-analyzer report",
        "",
        f"- events scanned: {len(events)}",
        f"- suspicious chains: {len(chains)}",
        f"- tool map: {args.tools} ({len(mapping)} tools, default={default_level})",
        "",
    ]
    for rank, c in enumerate(chains, 1):
        lines += [
            f"## {rank}. {c['rule']} (score {c['score']})",
            "",
            f"**Explanation:** {c['explanation']}",
            "",
            "**Sequence:**",
            "",
        ]
        for s in c["sequence"]:
            lines.append(
                f"- `#{s['index']}` {s['ts']} `{s['tool']}` — {s['level']} · {s['system']}"
            )
        lines += ["", "**Flowchart:**", "", "```mermaid", c["mermaid"], "```", ""]
    if not chains:
        lines += ["No suspicious chains found. 🎉", ""]

    report = "\n".join(lines)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(report)

    if args.json:
        serializable = [
            {k: v for k, v in c.items() if k != "mermaid"} for c in chains
        ]
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(serializable, fh, indent=2)

    print(f"scanned {len(events)} events -> {len(chains)} suspicious chain(s)")
    for rank, c in enumerate(chains, 1):
        print(f"  {rank}. [{c['rule']}] score={c['score']} :: {c['explanation']}")
    print(f"report written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
