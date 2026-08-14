#!/usr/bin/env python3
"""normalize.py — merge scanner outputs into one structural, machine-readable
stream (findings.jsonl). The pipeline NEVER emits prose reports; downstream
consumers (gates, vuln DBs, Slack, report renderers) read this.

Tool detection is by filename keyword:
  gitleaks / semgrep  → SARIF
  trivy               → Trivy JSON (config or image)
  grype               → Grype JSON
  zap                 → ZAP baseline JSON
  sbom                → CycloneDX (license inventory only)

Usage:
  normalize.py <scans-dir> --out findings.jsonl
"""
import argparse
import hashlib
import json
import pathlib
import sys

SARIF_LEVEL_SEV = {"error": "high", "warning": "medium", "note": "low"}


def fingerprint(tool: str, rule: str, path: str, line: int, snippet: str) -> str:
    """Stable finding identity: rule + location + code, NOT just the rule name.
    Used by gate.py to match expiring exceptions precisely."""
    raw = f"{tool}|{rule}|{path}|{line}|{snippet.strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def parse_sarif(data: dict, tool: str) -> list[dict]:
    out = []
    for run in data.get("runs", []):
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            art = loc.get("artifactLocation", {}) or {}
            region = loc.get("region", {}) or {}
            path = art.get("uri", "unknown")
            line = region.get("startLine", 0)
            snippet = (region.get("snippet") or {}).get("text", "")
            rule = res.get("ruleId", "unknown")
            level = res.get("level", "warning")
            out.append(
                {
                    "tool": tool,
                    "rule": rule,
                    "severity": SARIF_LEVEL_SEV.get(level, "medium"),
                    "path": path,
                    "line": line,
                    "snippet": snippet,
                    "message": (res.get("message") or {}).get("text", ""),
                    "fingerprint": fingerprint(tool, rule, path, line, snippet),
                    "metadata": {},
                }
            )
    return out


def _epss_score(v):
    epss = v.get("EPSS")
    if isinstance(epss, dict):
        return epss.get("score")
    if isinstance(epss, (int, float)):
        return epss
    return None


def parse_trivy(data: dict, tool: str) -> list[dict]:
    out = []
    for res in data.get("Results", []):
        target = res.get("Target", "?")
        for v in res.get("Vulnerabilities", []):
            out.append(
                {
                    "tool": tool,
                    "rule": v.get("VulnerabilityID", "?"),
                    "severity": (v.get("Severity") or "unknown").lower(),
                    "path": f"{target}:{v.get('PkgName', '?')}",
                    "line": 0,
                    "snippet": v.get("InstalledVersion", ""),
                    "message": v.get("Title", "")[:300],
                    "fingerprint": fingerprint(
                        tool, v.get("VulnerabilityID", "?"), f"{target}:{v.get('PkgName', '?')}", 0, v.get("InstalledVersion", "")
                    ),
                    "metadata": {
                        "known_exploited": bool(v.get("KnownExploited", False)),
                        "epss": _epss_score(v),
                        "fix_available": bool(v.get("FixedVersion")),
                    },
                }
            )
        for m in res.get("Misconfigurations", []):
            out.append(
                {
                    "tool": tool,
                    "rule": m.get("ID", "?"),
                    "severity": (m.get("Severity") or "unknown").lower(),
                    "path": target,
                    "line": m.get("CauseMetadata", {}).get("StartLine", 0) if isinstance(m.get("CauseMetadata"), dict) else 0,
                    "snippet": "",
                    "message": (m.get("Title") or "")[:200],
                    "fingerprint": fingerprint(tool, m.get("ID", "?"), target, 0, ""),
                    "metadata": {},
                }
            )
        for s in res.get("Secrets", []):
            out.append(
                {
                    "tool": tool,
                    "rule": f"trivy-secret-{s.get('RuleID', '?')}",
                    "severity": "high",
                    "path": target,
                    "line": s.get("StartLine", 0),
                    "snippet": "",
                    "message": s.get("Title", "")[:200],
                    "fingerprint": fingerprint(tool, f"trivy-secret-{s.get('RuleID', '?')}", target, s.get("StartLine", 0), ""),
                    "metadata": {},
                }
            )
    return out


def parse_grype(data: dict) -> list[dict]:
    out = []
    for m in data.get("matches", []):
        v = m.get("vulnerability", {})
        art = m.get("artifact", {})
        fix = m.get("fix", {})
        sev = (v.get("severity") or "unknown").lower()
        out.append(
            {
                "tool": "grype",
                "rule": v.get("id", "?"),
                "severity": sev,
                "path": f"{art.get('name', '?')}@{art.get('version', '?')}",
                "line": 0,
                "snippet": "",
                "message": v.get("description", "")[:300],
                "fingerprint": fingerprint("grype", v.get("id", "?"), f"{art.get('name', '?')}@{art.get('version', '?')}", 0, ""),
                "metadata": {
                    "known_exploited": bool(v.get("knownExploited", False)),
                    "epss": _epss_score(v),
                    "fix_available": bool(fix.get("versions")),
                },
            }
        )
    return out


def parse_zap(data: dict) -> list[dict]:
    out = []
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            risk = (a.get("riskdesc") or a.get("risk") or "unknown").lower()
            sev = risk.split("(")[0].strip().lower()
            out.append(
                {
                    "tool": "zap",
                    "rule": a.get("name", "?"),
                    "severity": sev,
                    "path": a.get("url", "?"),
                    "line": 0,
                    "snippet": a.get("evidence", "")[:100],
                    "message": (a.get("desc") or "")[:300],
                    "fingerprint": fingerprint("zap", a.get("name", "?"), a.get("url", "?"), 0, a.get("evidence", "")[:100]),
                    "metadata": {"cwe": a.get("cweid", "")},
                }
            )
    return out


def parse_cyclonedx_licenses(data: dict) -> list[dict]:
    """SBOM → license inventory. Licenses are findings at low severity; the
    gate's license policy decides whether they matter."""
    out = []
    for c in data.get("components", []):
        names = []
        for l in c.get("licenses", []) or []:
            lic = l.get("license") or {}
            names.append(lic.get("id") or lic.get("name") or "?")
        if names:
            out.append(
                {
                    "tool": "sbom",
                    "rule": "license",
                    "severity": "low",
                    "path": f"{c.get('name', '?')}@{c.get('version', '?')}",
                    "line": 0,
                    "snippet": "",
                    "message": "license: " + ", ".join(sorted(set(names))),
                    "fingerprint": fingerprint("sbom", "license", f"{c.get('name', '?')}@{c.get('version', '?')}", 0, ",".join(sorted(set(names)))),
                    "metadata": {"licenses": sorted(set(names))},
                }
            )
    return out


def load(path: pathlib.Path):
    return json.loads(path.read_text())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scans_dir", help="directory containing scanner outputs")
    ap.add_argument("--out", required=True, help="output findings.jsonl path")
    args = ap.parse_args()

    findings = []
    scans = pathlib.Path(args.scans_dir)
    for f in sorted(scans.iterdir()):
        if not f.is_file():
            continue
        name = f.name.lower()
        try:
            if "gitleaks" in name:
                findings += parse_sarif(load(f), "gitleaks")
            elif "semgrep" in name:
                findings += parse_sarif(load(f), "semgrep")
            elif "trivy" in name and f.suffix == ".json":
                findings += parse_trivy(load(f), "trivy")
            elif "trivy" in name and "sarif" in name:
                findings += parse_sarif(load(f), "trivy")
            elif "grype" in name:
                findings += parse_grype(load(f))
            elif "zap" in name:
                findings += parse_zap(load(f))
            elif "sbom" in name:
                findings += parse_cyclonedx_licenses(load(f))
        except Exception as exc:  # noqa: BLE001 - a broken input must not kill the gate
            print(f"normalize: WARN failed to parse {f.name}: {exc}", file=sys.stderr)

    with open(args.out, "w") as fh:
        for fd in findings:
            fh.write(json.dumps(fd) + "\n")

    print(f"normalize: {len(findings)} findings from {len(list(scans.iterdir()))} file(s) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
