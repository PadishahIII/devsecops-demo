#!/usr/bin/env python3
"""gate.py — the single policy decision point.

Consumes normalized findings (findings.jsonl) + policy + exceptions, computes
one action per finding, writes:
  - gate-decision.json  (full decision record, machine-readable)
  - audit/<file>.jsonl  (exception audit trail: applied / expired / unused)
and exits non-zero if anything fails — that is what blocks the pipeline.

Exit codes (status is also recorded in gate-decision.json):
  0 = PASS  — no blocking findings
  1 = WARN  — only warnings (map to UNSTABLE in CI)
  2 = FAIL  — blocking findings
  3 = ERROR — gate could not evaluate (absent findings/scan input).
              Fail-closed: an unavailable scan must never pass the pipeline.

Risk model (policy.yaml):
  severity defaults < KEV/EPSS overrides < tool overrides < exploitability
  class overrides < expiring exceptions. Severity alone is never the verdict.

The policy shape is typed with pydantic (Policy, SeverityDefaults,
FailWhenCondition, ExceptionsPolicy, LicensePolicy) — no string-literal
field access, unknown policy keys surface as validation errors at startup
instead of silently doing nothing.
"""
import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Literal, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

ACTION_ORDER = {"fail": 3, "warn": 2, "pass": 1}
MAX_SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4, "informational": 0, "unknown": 0}

# status -> exit code. FAIL 2 / ERROR 3 both block; the split lets the
# pipeline report *why* (policy verdict vs broken tooling) and map WARN
# to UNSTABLE instead of FAILURE.
STATUS_EXIT = {"pass": 0, "warn": 1, "fail": 2, "error": 3}

Severity = Literal["critical", "high", "medium", "low", "informational", "unknown"]
Action = Literal["fail", "warn", "pass"]
Status = Literal["pass", "warn", "fail", "error"]


class SeverityDefaults(BaseModel):
    model_config = {"extra": "forbid"}
    critical: Action = "fail"
    high: Action = "warn"
    medium: Action = "pass"
    low: Action = "pass"
    informational: Action = "pass"
    unknown: Action = "warn"


class FailWhenCondition(BaseModel):
    model_config = {"extra": "forbid"}
    field: str
    value: Optional[float | bool] = None
    op: str = ">="
    severities: list[Severity] = Field(default_factory=list)


class ExceptionsPolicy(BaseModel):
    model_config = {"extra": "forbid"}
    max_severity: Severity = "high"
    file: str = "security/exceptions.yaml"


class LicensePolicy(BaseModel):
    model_config = {"extra": "forbid"}
    fail: list[str] = Field(default_factory=list)
    warn: list[str] = Field(default_factory=list)


class Policy(BaseModel):
    model_config = {"extra": "forbid"}

    """Typed shape of security/policy.yaml. Unknown keys → validation error
    at startup (fail fast), so a typo cannot silently disable a control."""

    severity_defaults: SeverityDefaults = SeverityDefaults()
    fail_rule_classes: list[str] = Field(default_factory=list)
    fail_tools: list[str] = Field(default_factory=list)
    fail_when: list[FailWhenCondition] = Field(default_factory=list)
    exceptions: ExceptionsPolicy = ExceptionsPolicy()
    licenses: LicensePolicy = LicensePolicy()

    @field_validator("fail_when", mode="before")
    @classmethod
    def _default_fail_when(cls, v):
        return v or []

    @field_validator("fail_rule_classes", "fail_tools", mode="before")
    @classmethod
    def _default_lists(cls, v):
        return v or []


class ExceptionSpec(BaseModel):
    model_config = {"extra": "forbid"}

    """One entry of security/exceptions.yaml — an exact-fingerprint, expiring
    approval. Matching is exact, so an exception can never silently whitelist
    a whole rule; if the code moves the fingerprint stops matching and the
    finding fails closed."""

    id: str
    fingerprint: str
    rule: str = ""
    path: str = ""
    severity: str = "high"
    approved_by: str = ""
    date: str = ""
    expires: str = ""
    reason: str = ""
    ticket: str = ""

    @field_validator("severity", mode="before")
    @classmethod
    def _norm_sev(cls, v):
        return str(v).lower() if v else "high"

    @field_validator("date", "expires", mode="before")
    @classmethod
    def _norm_date(cls, v):
        return str(v or "")


def sev_at_least(sev, threshold):
    return MAX_SEV.get(sev, 0) >= MAX_SEV.get(threshold, 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("findings", help="findings.jsonl from normalize.py")
    ap.add_argument("policy", help="security/policy.yaml")
    ap.add_argument("exceptions", help="security/exceptions.yaml")
    ap.add_argument("--out", required=True, help="gate-decision.json output path")
    ap.add_argument("--findings-out", default=None,
                    help="write the GATED findings stream here (each finding + action/reason) — the input for tools/report.py")
    ap.add_argument("--audit", default="audit/exceptions-audit.jsonl")
    args = ap.parse_args()

    findings_path = Path(args.findings)
    if not findings_path.is_file() or findings_path.stat().st_size == 0:
        # Fail-closed: no findings stream = the gate could not evaluate.
        # An empty scans dir (scan stage broke) must never look like a pass.
        decision = {
            "status": "error",
            "date": dt.date.today().isoformat(),
            "counts": {"total": 0, "fail": 0, "warn": 0, "pass": 0},
            "failures": [],
            "warnings": [],
            "error": "missing findings input (normalize.py produced no findings.jsonl) — scan stage broken or empty",
        }
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(decision, indent=2) + "\n")
        print("gate: ERROR — no findings input; refusing to pass", file=sys.stderr)
        return STATUS_EXIT["error"]

    policy = Policy.model_validate(yaml.safe_load(Path(args.policy).read_text()))
    exc_specs = yaml.safe_load(Path(args.exceptions).read_text()) or []
    exceptions = {e.fingerprint: e for e in (ExceptionSpec.model_validate(e) for e in exc_specs)}

    findings = [json.loads(ln) for ln in findings_path.read_text().splitlines() if ln.strip()]

    fail_classes = [re.compile(p, re.IGNORECASE) for p in policy.fail_rule_classes]
    today = dt.date.today().isoformat()
    audit = []

    for f in findings:
        sev = f["severity"]
        action = policy.severity_defaults.model_dump().get(sev, "warn")
        reason = f"severity={sev}"

        # 1. tool override — secrets are categorical
        if f["tool"] in policy.fail_tools:
            action, reason = "fail", f"tool={f['tool']} is categorical"

        # 2. exploitability class override — injection/deserialization/RCE
        # FIXME: keyword matching is poor
        for rx in fail_classes:
            if rx.search(f["rule"] or ""):
                action, reason = "fail", f"exploitability class matched rule {f['rule']}"
                break

        # 3. KEV / EPSS overrides
        for cond in policy.fail_when:
            if sev not in cond.severities:
                continue
            val = f.get("metadata", {}).get(cond.field)
            if cond.field == "epss" and isinstance(val, (int, float)):
                if val >= cond.value:
                    action, reason = "fail", f"EPSS {val:.2f} >= {cond.value}"
            elif cond.field == "known_exploited" and val:
                action, reason = "fail", "known-exploited (KEV) — actively exploited in the wild"

        # 4. exception — exact fingerprint, expiring, severity-capped
        exc = exceptions.get(f["fingerprint"])
        if exc:
            if sev_at_least(sev, "critical") or MAX_SEV.get(sev, 0) > MAX_SEV.get(policy.exceptions.max_severity, 0):
                action, reason = "fail", "exception NOT allowed at this severity"
                audit.append({"event": "EXCEPTION_DENIED", "fingerprint": f["fingerprint"], "rule": f["rule"],
                              "severity": sev, "date": today, "exc_id": exc.id})
            elif exc.expires < today:
                action, reason = "fail", f"exception {exc.id} EXPIRED on {exc.expires}"
                audit.append({"event": "EXCEPTION_EXPIRED", "fingerprint": f["fingerprint"], "rule": f["rule"],
                              "severity": sev, "date": today, "exc_id": exc.id, "expires": exc.expires})
            else:
                action, reason = "warn", f"exception {exc.id} applied (expires {exc.expires})"
                audit.append({"event": "EXCEPTION_APPLIED", "fingerprint": f["fingerprint"], "rule": f["rule"],
                              "severity": sev, "date": today, "exc_id": exc.id,
                              "approved_by": exc.approved_by, "expires": exc.expires,
                              "ticket": exc.ticket, "reason": exc.reason})
        f["action"] = action
        f["reason"] = reason

    # exceptions that never matched any finding — audit trail completeness
    used = {f["fingerprint"] for f in findings}
    for fp_, e in exceptions.items():
        if fp_ not in used:
            audit.append({"event": "EXCEPTION_UNUSED", "fingerprint": fp_, "rule": e.rule,
                          "date": today, "exc_id": e.id, "note": "no finding matched — fail-closed? check rule/path/line drift"})

    # license policy from SBOM findings
    license_fail = policy.licenses.fail
    license_warn = policy.licenses.warn
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
    # An EMPTY findings stream is a legitimate pass (clean repo) —
    # absent input is the error case, handled above.
    status = "fail" if fails else ("warn" if warns else "pass")

    def _entry(f):
        return {"tool": f["tool"], "rule": f["rule"], "severity": f["severity"], "path": f["path"],
                "reason": f["reason"], "source": f.get("source", ""), "fingerprint": f.get("fingerprint", "")}
    decision = {
        "status": status,
        "date": today,
        "counts": {"total": len(findings), "fail": len(fails), "warn": len(warns), "pass": len(findings) - len(fails) - len(warns)},
        "failures": [_entry(f) for f in fails],
        "warnings": [_entry(f) for f in warns],
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(decision, indent=2) + "\n")
    if args.findings_out:
        Path(args.findings_out).parent.mkdir(parents=True, exist_ok=True)
        with open(args.findings_out, "w") as fh:
            for f in findings:
                fh.write(json.dumps(f) + "\n")
    Path(args.audit).parent.mkdir(parents=True, exist_ok=True)
    with open(args.audit, "a") as fh:
        for entry in audit:
            fh.write(json.dumps(entry) + "\n")

    print(f"gate: {status.upper()} — {len(fails)} fail, {len(warns)} warn, {len(findings) - len(fails) - len(warns)} pass")
    for f in fails:
        print(f"  FAIL  [{f['tool']}/{f['severity']}] {f['rule']} @ {f['path']} — {f['reason']}")
    for f in warns:
        print(f"  WARN  [{f['tool']}/{f['severity']}] {f['rule']} @ {f['path']} — {f['reason']}")
    return STATUS_EXIT[status]


if __name__ == "__main__":
    sys.exit(main())
