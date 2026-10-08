"""Command-line interface: spec + logs -> console table + JSON report."""
import argparse
import json
import sys
from pathlib import Path

from sadm.classifier import classify
from sadm.parser import SpecError, load_spec, read_logs
from sadm.scorer import score, severity

TYPES = ["SHADOW", "ZOMBIE", "ORPHAN", "DOCUMENTED", "NOISE"]


def build_findings(spec_ops: dict, records: list[dict], bases: list[str]) -> list[dict]:
    findings = []
    for f in classify(spec_ops, records, bases):
        pts, reasons = score(f)
        findings.append({
            "endpoint": f["endpoint"], "method": f["method"],
            "classification": f["classification"], "score": pts,
            "severity": severity(pts), "auth_gap": f["auth_gap"], "reasons": reasons,
            "requests": f["count"], "statuses": sorted(f["statuses"]),
        })
    # Highest risk first; ties broken deterministically.
    return sorted(findings, key=lambda x: (-x["score"], x["endpoint"], x["method"]))


def build_report(findings: list[dict]) -> dict:
    summary = {"total": len(findings)}
    summary.update({t.lower(): sum(f["classification"] == t for f in findings) for t in TYPES})
    summary["auth_gap"] = sum(f["auth_gap"] for f in findings)
    return {"summary": summary, "findings": findings}


def print_table(findings: list[dict], out=sys.stdout) -> None:
    print(f"{'Endpoint':<34}{'Method':<8}{'Type':<12}{'Score':<7}{'Severity':<10}Flags", file=out)
    print("-" * 80, file=out)
    for f in findings:
        print(f"{f['endpoint']:<34}{f['method']:<8}{f['classification']:<12}"
              f"{f['score']:<7}{f['severity']:<10}{'AUTH-GAP' if f['auth_gap'] else ''}", file=out)


def compare(findings: list[dict], baseline_file: str) -> None:
    """Stretch goal: diff this scan against another report (e.g. vulnerable vs secure mode)."""
    base = json.loads(Path(baseline_file).read_text(encoding="utf-8"))["findings"]
    old = {(f["method"], f["endpoint"]): f for f in base}
    new = {(f["method"], f["endpoint"]): f for f in findings}
    show = lambda f: f"{f['classification']} {f['score']} {f['statuses']}" if f else "absent"
    print(f"\nComparison (this scan vs baseline {baseline_file})")
    diffs = [k for k in sorted(new.keys() | old.keys())
             if show(new.get(k)) != show(old.get(k))]
    for k in diffs:
        print(f"  {k[0]:<7}{k[1]:<32} this: {show(new.get(k)):<28} baseline: {show(old.get(k))}")
    print(f"  {len(diffs)} difference(s)" if diffs else "  no differences")


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="sadm", description="Shadow API Discovery Module (passive)")
    p.add_argument("--spec", required=True, help="OpenAPI 3.x spec (.yaml/.yml/.json)")
    p.add_argument("--logs", required=True, help="JSON-lines access log")
    p.add_argument("--output", default="report.json", help="JSON report path")
    p.add_argument("--baseline", help="another SADM report to compare against (e.g. secure mode)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        spec_ops, bases = load_spec(args.spec)
        records, errors = read_logs(args.logs)
    except SpecError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for err in errors:
        print(f"warning: skipped log {err}", file=sys.stderr)
    findings = build_findings(spec_ops, records, bases)
    report = build_report(findings)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print_table(findings)
    print("\n" + "  ".join(f"{k}={v}" for k, v in report["summary"].items()))
    print(f"Skipped log lines: {len(errors)} | Report written to {out}")
    if args.baseline:
        try:
            compare(findings, args.baseline)
        except (OSError, ValueError, KeyError) as exc:
            print(f"error: cannot compare with baseline: {exc}", file=sys.stderr)
            return 2
    return 0
