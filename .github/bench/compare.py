#!/usr/bin/env python3
"""Compare interleaved corosio benchmark runs.

summarize: reduce raw per-iteration JSON (base/head × backend) to one
per-platform summary with flagging.
report: merge per-platform summaries into the PR comment markdown.

Input files: <side>-<backend>-<iter>.json as written by
corosio_bench --output. Never exits nonzero because of suite-shape
differences between base and head; only real I/O or usage errors fail.
"""
import argparse
import json
import re
import statistics
import sys
from pathlib import Path

MIN_EFFECT_PCT = 2.0
NOISE_FACTOR = 3.0
HIGHER_BETTER = ("bytes_per_sec", "items_per_sec", "ops_per_sec")
FNAME = re.compile(r"^(base|head)-([A-Za-z0-9_]+)-(\d+)\.json$")


def primary_metric(category, metrics):
    """Pick the compared metric and its direction for one benchmark."""
    if "latency" in category and "latency_mean_ns" in metrics:
        return "latency_mean_ns", "lower"
    for m in HIGHER_BETTER:
        if m in metrics:
            return m, "higher"
    if "latency_mean_ns" in metrics:
        return "latency_mean_ns", "lower"
    return None, None


def load_runs(input_dir):
    """Return {(side, backend, iter): {(category, name): {metric: value}}}."""
    runs = {}
    for p in sorted(Path(input_dir).iterdir()):
        m = FNAME.match(p.name)
        if not m:
            continue
        side, backend, it = m.group(1), m.group(2), int(m.group(3))
        try:
            payload = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError) as e:
            print(f"warning: skipping unreadable {p.name}: {e}", file=sys.stderr)
            continue
        table = {}
        for b in payload.get("benchmarks", []):
            key = (b.get("category", ""), b.get("name", ""))
            table[key] = {
                k: v for k, v in b.items()
                if isinstance(v, (int, float)) and not isinstance(v, bool)
            }
        runs[(side, backend, it)] = table
    return runs


def _values(runs, side, backend, key, metric):
    """Metric samples for one benchmark on one side, ordered by iteration."""
    out = []
    for (s, b, it), table in sorted(runs.items(), key=lambda kv: kv[0][2]):
        if s == side and b == backend and key in table and metric in table[key]:
            out.append((it, table[key][metric]))
    return out


def summarize(input_dir, platform, mode="ab"):
    runs = load_runs(input_dir)
    backends = sorted({b for (_, b, _) in runs})
    iterations = max((it for (_, _, it) in runs), default=0)
    duration = 0.0
    rows, new, removed, unsupported = [], [], [], []

    for backend in backends:
        base_keys, head_keys = set(), set()
        sample = {}
        for (s, b, it), table in runs.items():
            if b != backend:
                continue
            (base_keys if s == "base" else head_keys).update(table)
            for key, metrics in table.items():
                sample.setdefault(key, metrics)

        for key in sorted(base_keys | head_keys):
            category, name = key
            metric, direction = primary_metric(category, sample.get(key, {}))
            if metric is None:
                unsupported.append(
                    {"backend": backend, "category": category, "name": name})
                continue
            if key not in base_keys:
                head = _values(runs, "head", backend, key, metric)
                mean = statistics.fmean(v for _, v in head) if head else 0.0
                new.append({"backend": backend, "category": category,
                            "name": name, "metric": metric, "head_mean": mean})
                continue
            if key not in head_keys:
                removed.append(
                    {"backend": backend, "category": category, "name": name})
                continue

            base = dict(_values(runs, "base", backend, key, metric))
            head = dict(_values(runs, "head", backend, key, metric))
            common = sorted(set(base) & set(head))
            deltas = []
            for it in common:
                b_v, h_v = base[it], head[it]
                if b_v == 0:
                    continue
                d = (h_v - b_v) / b_v * 100.0
                if direction == "lower":
                    d = -d
                deltas.append(d)
            if not deltas:
                unsupported.append(
                    {"backend": backend, "category": category, "name": name})
                continue

            base_vals = [base[it] for it in common]
            base_mean = statistics.fmean(base_vals)
            head_mean = statistics.fmean(head[it] for it in common)
            noise_pct = None
            if len(base_vals) >= 2 and base_mean != 0:
                noise_pct = statistics.stdev(base_vals) / abs(base_mean) * 100.0
            delta_pct = statistics.fmean(deltas)
            flagged = (
                noise_pct is not None
                and abs(delta_pct) > max(MIN_EFFECT_PCT, NOISE_FACTOR * noise_pct)
            )
            rows.append({
                "backend": backend, "category": category, "name": name,
                "metric": metric, "direction": direction,
                "base_mean": base_mean, "head_mean": head_mean,
                "delta_pct": delta_pct, "noise_pct": noise_pct,
                "flagged": flagged,
            })

    for p in Path(input_dir).iterdir():
        if FNAME.match(p.name):
            try:
                duration = json.loads(p.read_text())["metadata"]["duration_s"]
                break
            except Exception:
                pass

    return {
        "platform": platform, "backends": backends,
        "iterations": iterations, "duration_s": duration, "mode": mode,
        "rows": rows, "new": new, "removed": removed,
        "unsupported": unsupported,
        "flagged_count": sum(1 for r in rows if r["flagged"]),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="compare.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("summarize")
    s.add_argument("--platform", required=True)
    s.add_argument("--input-dir", required=True)
    s.add_argument("--output", required=True)
    s.add_argument("--mode", default="ab", choices=("ab", "aa"))
    args = ap.parse_args(argv)

    if args.cmd == "summarize":
        summary = summarize(args.input_dir, args.platform, args.mode)
        Path(args.output).write_text(json.dumps(summary, indent=2))
        print(f"{args.platform}: {len(summary['rows'])} rows, "
              f"{summary['flagged_count']} flagged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
