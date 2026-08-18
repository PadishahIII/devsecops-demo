#!/usr/bin/env python3
"""normalize.py — extract a lean, structural gating stream from scanner
outputs. The raw artifacts stay untouched; the findings stream is the
gate's interface, and the per-finding `source` pointer plus the raw files
remain available for detailed reporting later.

  findings.jsonl:  one line per finding — the fields the gate needs
                   (tool, rule, severity, path, line, message, metadata,
                   fingerprint) + `source` = path of the raw artifact
  raw/            : the original scanner outputs (e.g. gitleaks.sarif),
                   copied next to the findings so later consumers can
                   produce detailed reports from the source of truth
                   without re-running the scanners

Tool detection is by filename keyword:
  gitleaks / semgrep  → SARIF
  trivy               → Trivy JSON (config or image) or SARIF
  grype               → Grype JSON
  zap                 → ZAP baseline JSON
  sbom                → CycloneDX (license inventory only)

SARIF severity notes (observed on gitleaks v8.21.2, semgrep 1.155.0,
trivy 0.74.0):
  * gitleaks emits results WITHOUT a `level` field and no rules table —
    all findings default to "medium" (secrets are categorical via the
    gate's fail_tools anyway).
  * semgrep (incl. --sarif) emits results with NO `level` and NO
    `ruleIndex` — severity lives only in
    runs[].tool.driver.rules[i].defaultConfiguration.level; looked up by
    rule id, missing rules default to "warning".
  * trivy (incl. custom Rego checks, single-entry rules table) also
    omits `ruleIndex` → resolved by rule id, falling back to index 0.

Usage:
  normalize.py <scans-dir> --out findings.jsonl [--raw-dir raw]
"""
import argparse
import hashlib
import json
import pathlib
import shutil
import sys

from pydantic import BaseModel, Field

SARIF_LEVEL_SEV = {"error": "high", "warning": "medium", "note": "low"}

# trivy emits a single-rule rules table; results carry no ruleIndex.
TRIVY_SINGLE_RULE_INDEX = 0


class Finding(BaseModel):
    """One normalized finding. This is the gate's interface — the fields a
    policy can see. Full detail stays in the raw artifact, referenced via
    `source` (see the DESIGN.md §4.2 finding schema)."""

    tool: str
    rule: str
    severity: str
    path: str = ""
    line: int = 0
    snippet: str = ""
    message: str = ""
    fingerprint: str
    metadata: dict = Field(default_factory=dict)
    source: str = ""  # raw artifact file this finding came from


def fingerprint(tool: str, rule: str, path: str, line: int, snippet: str) -> str:
    """Stable finding identity: rule + location + code, NOT just the rule name.
    Used by gate.py to match expiring exceptions precisely.

    Path is normalized (leading '/' trimmed) and snippet is stripped so the
    hash does not depend on the SARIF artifact URI base (e.g. /src/ vs .) or
    on indentation — an exception fingerprint written against the relative
    path + stripped snippet (DESIGN.md §4.2) still matches."""
    path = path.lstrip("/")
    raw = f"{tool}|{rule}|{path}|{line}|{snippet.strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _rule_severity_map(run: dict) -> dict[str, str]:
    """SARIF rules table → {rule id: normalized severity}.

    Vendors disagree about where severity lives:
      * semgrep:   result has no `level`, rule table is authoritative
      * gitleaks:  no `level` anywhere → default "medium" (gate handles it)
      * trivy:     result HAS `level` (error/warning/note) → table is a fallback
    """
    out: dict[str, str] = {}
    for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
        if not isinstance(rule, dict):
            continue
        level = rule.get("defaultConfiguration", {}).get("level")
        out[rule.get("id", "?")] = SARIF_LEVEL_SEV.get(level, "medium")
    return out


def _result_severity(res: dict, rule_sev: dict[str, str]) -> str:
    """Result severity: explicit `level` wins; else rules table by rule id;
    else trivy-style single-rule table; else default "warning" (SARIF spec)."""
    level = res.get("level")
    if level:
        return SARIF_LEVEL_SEV.get(level, "medium")
    rule_id = res.get("ruleId")
    if rule_id and rule_id in rule_sev:
        return rule_sev[rule_id]
    if len(rule_sev) == 1 and TRIVY_SINGLE_RULE_INDEX == 0:
        return next(iter(rule_sev.values()))
    return "warning"


def parse_sarif(data: dict, tool: str, source: str) -> list[dict]:
    out = []
    for run in data.get("runs", []):
        rule_sev = _rule_severity_map(run)
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            art = loc.get("artifactLocation", {}) or {}
            region = loc.get("region", {}) or {}
            path = art.get("uri", "unknown")
            line = region.get("startLine", 0)
            snippet = (region.get("snippet") or {}).get("text", "")
            rule = res.get("ruleId", "unknown")
            # gitleaks stores commit context in partialFingerprints; it is
            # essential for a secret report (who leaked, when) — keep it.
            pfp = res.get("partialFingerprints") or {}
            metadata = {"commit": pfp} if isinstance(pfp, dict) and pfp else {}
            out.append(
                Finding(
                    tool=tool,
                    rule=rule,
                    severity=_result_severity(res, rule_sev),
                    path=path,
                    line=line,
                    snippet=snippet,
                    message=(res.get("message") or {}).get("text", ""),
                    fingerprint=fingerprint(tool, rule, path, line, snippet),
                    metadata=metadata,
                    source=source,
                )
            )
    return [f.model_dump() for f in out]

def _epss_score(v: dict):
    """Grype stores EPSS as a LIST of {cve, epss, percentile, date} records
    (since ~0.115); trivy used a plain {EPSS: {score}} dict. Both are handled."""
    epss = v.get("epss") or v.get("EPSS")
    if isinstance(epss, dict):
        return epss.get("score")
    if isinstance(epss, list):
        return epss[0].get("epss") if epss else None
    if isinstance(epss, (int, float)):
        return epss
    return None


def parse_trivy(data: dict, tool: str, source: str) -> list[dict]:
    out = []
    for res in data.get("Results", []):
        target = res.get("Target", "?")
        for v in res.get("Vulnerabilities", []):
            out.append(
                Finding(
                    tool=tool,
                    rule=v.get("VulnerabilityID", "?"),
                    severity=(v.get("Severity") or "unknown").lower(),
                    path=f"{target}:{v.get('PkgName', '?')}",
                    snippet=v.get("InstalledVersion", ""),
                    message=v.get("Title", "")[:300],
                    fingerprint=fingerprint(
                        tool, v.get("VulnerabilityID", "?"), f"{target}:{v.get('PkgName', '?')}", 0, v.get("InstalledVersion", "")
                    ),
                    metadata={
                        "known_exploited": bool(v.get("KnownExploited", False)),
                        "epss": _epss_score(v),
                        "fix_available": bool(v.get("FixedVersion")),
                    },
                    source=source,
                )
            )
        for m in res.get("Misconfigurations", []):
            cause = m.get("CauseMetadata") if isinstance(m.get("CauseMetadata"), dict) else {}
            out.append(
                Finding(
                    tool=tool,
                    rule=m.get("ID", "?"),
                    severity=(m.get("Severity") or "unknown").lower(),
                    path=target,
                    line=cause.get("StartLine", 0),
                    message=(m.get("Title") or "")[:200],
                    fingerprint=fingerprint(tool, m.get("ID", "?"), target, 0, ""),
                    source=source,
                )
            )
        for s in res.get("Secrets", []):
            out.append(
                Finding(
                    tool=tool,
                    rule=f"trivy-secret-{s.get('RuleID', '?')}",
                    severity="high",
                    path=target,
                    line=s.get("StartLine", 0),
                    message=s.get("Title", "")[:200],
                    fingerprint=fingerprint(tool, f"trivy-secret-{s.get('RuleID', '?')}", target, s.get("StartLine", 0), ""),
                    source=source,
                )
            )
    return [f.model_dump() for f in out]


def parse_grype(data: dict, source: str) -> list[dict]:
    out = []
    for m in data.get("matches", []):
        v = m.get("vulnerability", {})
        art = m.get("artifact", {})
        fix = m.get("fix") or v.get("fix") or {}  # grype: fix may live under match OR vulnerability
        sev = (v.get("severity") or "unknown").lower()
        out.append(
            Finding(
                tool="grype",
                rule=v.get("id", "?"),
                severity=sev,
                path=f"{art.get('name', '?')}@{art.get('version', '?')}",
                message=v.get("description", "")[:300],
                fingerprint=fingerprint("grype", v.get("id", "?"), f"{art.get('name', '?')}@{art.get('version', '?')}", 0, ""),
                metadata={
                    "known_exploited": bool(v.get("knownExploited", False)),
                    "epss": _epss_score(v),
                    "fix_available": bool(fix.get("versions")),
                },
                source=source,
            )
        )
    return [f.model_dump() for f in out]


def parse_zap(data: dict, source: str) -> list[dict]:
    out = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            risk = (a.get("riskdesc") or a.get("risk") or "unknown").lower()
            sev = risk.split("(")[0].strip().lower()
            out.append(
                Finding(
                    tool="zap",
                    rule=a.get("name", "?"),
                    severity=sev,
                    path=a.get("url", "?"),
                    snippet=a.get("evidence", "")[:100],
                    message=(a.get("desc") or "")[:300],
                    fingerprint=fingerprint("zap", a.get("name", "?"), a.get("url", "?"), 0, a.get("evidence", "")[:100]),
                    metadata={"cwe": a.get("cweid", "")},
                    source=source,
                )
            )
    return [f.model_dump() for f in out]


def parse_cyclonedx_licenses(data: dict, source: str) -> list[dict]:
    """SBOM → license inventory. Licenses are findings at low severity; the
    gate's license policy decides whether they matter."""
    out = []
    for c in data.get("components", []):
        names = []
        for lc in c.get("licenses", []) or []:
            lic = lc.get("license") or {}
            names.append(lic.get("id") or lic.get("name") or "?")
        if names:
            out.append(
                Finding(
                    tool="sbom",
                    rule="license",
                    severity="low",
                    path=f"{c.get('name', '?')}@{c.get('version', '?')}",
                    message="license: " + ", ".join(sorted(set(names))),
                    fingerprint=fingerprint("sbom", "license", f"{c.get('name', '?')}@{c.get('version', '?')}", 0, ",".join(sorted(set(names)))),
                    metadata={"licenses": sorted(set(names))},
                    source=source,
                )
            )
    return [f.model_dump() for f in out]


def load(path: pathlib.Path):
    return json.loads(path.read_text())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scans_dir", help="directory containing scanner outputs")
    ap.add_argument("--out", required=True, help="output findings.jsonl path")
    ap.add_argument("--raw-dir", default="raw", help="copy raw artifacts here (default: raw/)")
    args = ap.parse_args()

    scans = pathlib.Path(args.scans_dir)
    raw_out = pathlib.Path(args.raw_dir)
    findings = []

    for f in sorted(scans.iterdir()):
        if not f.is_file():
            continue
        name = f.name.lower()
        try:
            if "gitleaks" in name:
                findings += parse_sarif(load(f), "gitleaks", f.name)
            elif "semgrep" in name:
                findings += parse_sarif(load(f), "semgrep", f.name)
            elif "trivy" in name and f.suffix == ".json":
                findings += parse_trivy(load(f), "trivy", f.name)
            elif "trivy" in name and "sarif" in name:
                findings += parse_sarif(load(f), "trivy", f.name)
            elif "grype" in name:
                findings += parse_grype(load(f), f.name)
            elif "zap" in name:
                findings += parse_zap(load(f), f.name)
            elif "sbom" in name:
                findings += parse_cyclonedx_licenses(load(f), f.name)
        except Exception as exc:  # noqa: BLE001 - a broken input must not kill the gate
            print(f"normalize: WARN failed to parse {f.name}: {exc}", file=sys.stderr)
            continue
        # raw artifact stays available for detailed reports
        raw_out.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, raw_out / f.name)

    with open(args.out, "w") as fh:
        for fd in findings:
            fh.write(json.dumps(fd) + "\n")

    print(f"normalize: {len(findings)} findings from {len(list(scans.iterdir()))} file(s) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
