#!/usr/bin/env python3
"""gate.py — the single policy decision point.

Consumes normalized findings (findings.jsonl) + policy + exceptions, computes
one action per finding, writes:
  - gate-decision.json  (full decision record, machine-readable)
  - audit/<file>.jsonl  (exception audit trail: applied / expired / unused)
and exits non-zero if anything fails — that is what blocks the pipeline.

Risk model (policy.yaml):
  severity defaults < KEV/EPSS overrides < tool overrides < exploitability
  class overrides < expiring exceptions. Severity alone is never the verdict.
"""
import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

import yaml

ACTION_ORDER = {"fail": 3, "warn": 2, "pass": 1}
MAX_SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4, "informational": 0, "unknown": 0}


def sev_at_least(sev, threshold):
    return MAX_SEV.get(sev, 0) >= MAX_SEV.get(threshold, 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("findings", help="findings.jsonl from normalize.py")
    ap.add_argument("policy", help="security/policy.yaml")
    ap.add_argument("exceptions", help="security/exceptions.yaml")
    ap.add_argument("--out", required=True, help="gate-decision.json output path")
    ap.add_argument("--audit", default="audit/exceptions-audit.jsonl")
    args = ap.parse_args()

    policy = yaml.safe_load(Path(args.policy).read_text())
    exc_specs = yaml.safe_load(Path(args.exceptions).read_text()) or []
    exceptions = {e["fingerprint"]: e for e in exc_specs}

    findings = [json.loads(l) for l in Path(args.findings).read_text().splitlines() if l.strip()]

    fail_classes = [re.compile(p, re.IGNORECASE) for p in policy.get("fail_rule_classes", [])]
    today = dt.date.today().isoformat()
    audit = []

    for f in findings:
        sev = f["severity"]
        action = policy.get("severity_defaults", {}).get(sev, "warn")
        reason = f"severity={sev}"

        # 1. tool override — secrets are categorical
        if f["tool"] in policy.get("fail_tools", []):
            action, reason = "fail", f"tool={f['tool']} is categorical"

        # 2. exploitability class override — injection/deserialization/RCE
        for rx in fail_classes:
            if rx.search(f["rule"] or ""):
                action, reason = "fail", f"exploitability class matched rule {f['rule']}"
                break

        # 3. KEV / EPSS overrides
        for cond in policy.get("fail_when", []):
            if sev not in cond["severities"]:
                continue
            val = f.get("metadata", {}).get(cond["field"])
            if cond["field"] == "epss" and isinstance(val, (int, float)):
                if val >= cond.get("value", 0.9):
                    action, reason = "fail", f"EPSS {val:.2f} >= {cond.get('value', 0.9)}"
            elif cond["field"] == "known_exploited" and val:
                action, reason = "fail", "known-exploited (KEV) — actively exploited in the wild"

        # 4. exception — exact fingerprint, expiring, severity-capped
        exc = exceptions.get(f["fingerprint"])
        if exc:
            if sev_at_least(sev, "critical") or MAX_SEV.get(sev, 0) > MAX_SEV.get(policy.get("exceptions", {}).get("max_severity", "high"), 0):
                action, reason = "fail", "exception NOT allowed at this severity"
                audit.append({"event": "EXCEPTION_DENIED", "fingerprint": f["fingerprint"], "rule": f["rule"],
                              "severity": sev, "date": today, "exc_id": exc.get("id")})
            elif exc.get("expires", "1970-01-01") < today:
                action, reason = "fail", f"exception {exc.get('id')} EXPIRED on {exc['expires']}"
                audit.append({"event": "EXCEPTION_EXPIRED", "fingerprint": f["fingerprint"], "rule": f["rule"],
                              "severity": sev, "date": today, "exc_id": exc.get("id"), "expires": exc.get("expires")})
            else:
                action, reason = "warn", f"exception {exc.get('id')} applied (expires {exc.get('expires')})"
                audit.append({"event": "EXCEPTION_APPLIED", "fingerprint": f["fingerprint"], "rule": f["rule"],
                              "severity": sev, "date": today, "exc_id": exc.get("id"),
                              "approved_by": exc.get("approved_by"), "expires": exc.get("expires"),
                              "ticket": exc.get("ticket"), "reason": exc.get("reason")})
        f["action"] = action
        f["reason"] = reason

    # exceptions that never matched any finding — audit trail completeness
    used = {f["fingerprint"] for f in findings}
    for fp_, e in exceptions.items():
        if fp_ not in used:
            audit.append({"event": "EXCEPTION_UNUSED", "fingerprint": fp_, "rule": e.get("rule"),
                          "date": today, "exc_id": e.get("id"), "note": "no finding matched — fail-closed? check rule/path/line drift"})

    # license policy from SBOM findings
    license_fail = policy.get("licenses", {}).get("fail", [])
    license_warn = policy.get("licenses", {}).get("warn", [])
    for f in findings:
        if f.get("rule") != "license":
            continue
        for lic in f.get("metadata", {}).get("licenses", []):
            if lic in license_fail:
                f["action"], f["reason"] = "fail", f"license {lic} is blocked"
            elif lic in license_warn:
                f["action"], f["reason"] = "warn", f"license {lic} requires review"

    fails = [f for f in findings if f.get("action") == "fail"]
    warns = [f for f in findings if f.get("action") == "warn"]
    status = "fail" if fails else "pass"

    decision = {
        "status": status,
        "date": today,
        "counts": {"total": len(findings), "fail": len(fails), "warn": len(warns), "pass": len(findings) - len(fails) - len(warns)},
        "failures": [{"tool": f["tool"], "rule": f["rule"], "severity": f["severity"], "path": f["path"], "reason": f["reason"]} for f in fails],
        "warnings": [{"tool": f["tool"], "rule": f["rule"], "severity": f["severity"], "path": f["path"], "reason": f["reason"]} for f in warns],
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(decision, indent=2) + "\n")
    Path(args.audit).parent.mkdir(parents=True, exist_ok=True)
    with open(args.audit, "a") as fh:
        for entry in audit:
            fh.write(json.dumps(entry) + "\n")

    print(f"gate: {status.upper()} — {len(fails)} fail, {len(warns)} warn, {len(findings) - len(fails) - len(warns)} pass")
    for f in fails:
        print(f"  FAIL  [{f['tool']}/{f['severity']}] {f['rule']} @ {f['path']} — {f['reason']}")
    for f in warns:
        print(f"  WARN  [{f['tool']}/{f['severity']}] {f['rule']} @ {f['path']} — {f['reason']}")
    return 1 if status == "fail" else 0


if __name__ == "__main__":
    sys.exit(main())
