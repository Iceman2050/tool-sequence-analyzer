"""Core analysis engine for tool-sequence-analyzer (stdlib only)."""
import json
import re

LEVELS = {
    "read-low": 1,
    "read-sensitive": 2,
    "write-low": 3,
    "write-sensitive": 4,
    "admin": 5,
}

SEVERITY = {
    "data-smuggling": 30,
    "cross-boundary": 20,
    "escalation": 10,
}

_SYSTEM_ARG_KEYS = ("system", "service", "target_system", "destination", "account")


def parse_tools_yaml(text):
    """Parse a tiny subset of YAML: `tool.name: level` mappings.

    Accepts an optional `tools:` section header and a `default_level:` key.
    Comments (# ...) and blank lines are ignored.
    """
    mapping = {}
    default_level = "read-low"
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        m = re.match(r"^\s*([\w.\-/:]+)\s*:\s*([\w\-]+)\s*$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if key == "tools":
            continue
        if key == "default_level":
            if val in LEVELS:
                default_level = val
            continue
        if val in LEVELS:
            mapping[key] = val
    return mapping, default_level


def load_tool_map(path):
    with open(path, "r", encoding="utf-8") as fh:
        return parse_tools_yaml(fh.read())


def load_events(path):
    events = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue  # skip malformed lines, don't die on messy logs
            if isinstance(obj, dict) and "tool" in obj:
                obj["_lineno"] = lineno
                events.append(obj)
    return events


def level_of(event, mapping, default_level="read-low"):
    return mapping.get(event.get("tool", ""), default_level)


def system_of(event):
    args = event.get("args") or {}
    if isinstance(args, dict):
        for key in _SYSTEM_ARG_KEYS:
            val = args.get(key)
            if val:
                return str(val)
    tool = str(event.get("tool", ""))
    parts = re.split(r"[./:]", tool, 1)
    return parts[0] if len(parts) > 1 else "default"


_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-\./:@]{11,}")


def interesting_tokens(text):
    """Long opaque-looking tokens that could be exfiltrated data/credentials."""
    if not text:
        return []
    seen = []
    for tok in _TOKEN_RE.findall(str(text)):
        if tok not in seen:
            seen.append(tok)
    return seen


def _make_chain(events, start, end, rule, explanation, score_bonus=0):
    seq = []
    for i in range(start, end + 1):
        e = events[i]
        seq.append(
            {
                "index": i,
                "ts": e.get("ts", ""),
                "tool": e.get("tool", ""),
                "level": e.get("_level", "?"),
                "system": e.get("_system", "?"),
            }
        )
    return {
        "rule": rule,
        "score": SEVERITY[rule] + score_bonus,
        "start": start,
        "end": end,
        "explanation": explanation,
        "sequence": seq,
    }


def chain_to_mermaid(chain):
    """Render a flagged chain as a Mermaid flowchart."""
    lines = ["flowchart LR"]
    seq = chain["sequence"]
    for n, step in enumerate(seq):
        label = (
            f"#{step['index']} {step['ts']}<br/>"
            f"{step['tool']}<br/>"
            f"{step['level']} · {step['system']}"
        )
        # escape quotes for mermaid safety
        label = label.replace('"', "'")
        lines.append(f'    n{n}["{label}"]')
    for n in range(len(seq) - 1):
        edge = f" -- {chain['rule']} -->" if n == 0 else " -->"
        lines.append(f"    n{n}{edge} n{n + 1}")
    expl = chain["explanation"].replace('"', "'")
    lines.append(f'    note["⚠ {expl}"]')
    lines.append(f"    n{len(seq) - 1} --> note")
    lines.append("    classDef bad fill:#f96,stroke:#333;")
    lines.append(f"    class n{len(seq) - 1},note bad;")
    return "\n".join(lines)


def analyze(events, mapping, default_level="read-low", window=6):
    """Detect privilege-escalation patterns. Returns ranked chain dicts."""
    for e in events:
        e["_level"] = level_of(e, mapping, default_level)
        e["_system"] = system_of(e)

    chains = []
    seen = set()
    n = len(events)

    def emit(chain):
        key = (chain["rule"], chain["start"], chain["end"])
        if key not in seen:
            seen.add(key)
            chains.append(chain)

    # Pre-index tokens from every result_summary for the smuggling rule.
    result_tokens = [interesting_tokens(e.get("result_summary")) for e in events]

    for i, e in enumerate(events):
        lvl = e["_level"]

        # (b) escalation: read-low -> write-sensitive anywhere in window
        if lvl == "read-low":
            for j in range(i + 1, min(i + 1 + window, n)):
                if events[j]["_level"] == "write-sensitive":
                    emit(
                        _make_chain(
                            events,
                            i,
                            j,
                            "escalation",
                            f"read-low tool '{e['tool']}' at #{i} precedes "
                            f"write-sensitive tool '{events[j]['tool']}' at #{j}",
                        )
                    )
                    break

        # (a) cross-boundary: read-sensitive -> write-sensitive on a DIFFERENT system
        if lvl == "read-sensitive":
            for j in range(i + 1, min(i + 1 + window, n)):
                f = events[j]
                if f["_level"] == "write-sensitive" and f["_system"] != e["_system"]:
                    emit(
                        _make_chain(
                            events,
                            i,
                            j,
                            "cross-boundary",
                            f"read-sensitive '{e['tool']}' (system '{e['_system']}') at #{i} "
                            f"feeds write-sensitive '{f['tool']}' (system '{f['_system']}') at #{j}",
                        )
                    )
                    break

        # (c) data smuggling: admin call whose args contain data first seen in a result
        if lvl == "admin":
            args_str = json.dumps(e.get("args") or {}, sort_keys=True)
            lo = max(0, i - window)
            for k in range(lo, i):
                hit = None
                for tok in result_tokens[k]:
                    if tok and tok in args_str:
                        hit = tok
                        break
                if hit:
                    emit(
                        _make_chain(
                            events,
                            k,
                            i,
                            "data-smuggling",
                            f"admin tool '{e['tool']}' at #{i} has args containing "
                            f"'{hit[:32]}' first seen in result of '{events[k]['tool']}' at #{k}",
                            score_bonus=min(len(hit), 20),
                        )
                    )
                    break

    chains.sort(key=lambda c: (-c["score"], c["start"]))
    for c in chains:
        c["mermaid"] = chain_to_mermaid(c)
    return chains
