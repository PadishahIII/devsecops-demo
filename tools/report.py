#!/usr/bin/env python3
"""report.py — curated human report from the gated findings stream.

Consumes the GATED findings stream (gate.py --findings-out) + gate-decision.json
and writes a self-contained `report.md` (plus a copy of the raw artifacts under
`raw/`) into the DIRECTORY given by --out.

Why a report on top of the structural stream (DESIGN.md §4):
  * findings.jsonl is the *gate's* interface — lean on purpose; full detail
    stays in the raw artifacts behind the per-finding `source` pointer.
  * gate-decision.json is machine-readable but unreadable by humans: 17
    findings → 11 fail / 4 warn / 2 pass says nothing about *what* to fix.
  * This tool closes the loop: it groups the gated findings per tool and
    renders each class of finding with the format that fits it —
      SAST          : source-code locations so the whole vuln path can be
                      reviewed (source file → sink line, from code + semgrep
                      metadata)
      secret scan   : affected file/line + commit metadata (gitleaks
                      partialFingerprints: author, commit, date)
      image SCA     : package@version + vuln id + CVSS/EPSS/KEV/fix + advisory
                      URLs (from grype/trivy JSON, enriched by normalize)
      misconfig     : resource (target) + check id + line + rule description
                      (trivy config: KSV-0014 & friends, incl. custom Rego
                      checks from security/trivy/*.rego)
      license       : component + detected licenses, split into blocked /
                      review / informational per policy
  * Findings are deduplicated by fingerprint *within a tool* (normalize keeps
    one entry per raw artifact, and both a full and a repro scan may feed the
    stream — e.g. gitleaks.sarif + gitleaks-full.sarif + gitleaks-repro.sarif).
  * Every table links the fingerprint back to the raw artifact in raw/ so the
    reader can always open the source of truth.

Policy summary (security/policy.yaml) is included so the report explains the
*why* of each verdict, not just the what. Statuses are FAIL / WARN / PASS /
EXCEPTED (a warning backed by an expiring exception).

Usage:
  normalize.py <scans-dir> --out findings.jsonl --raw-dir raw
  gate.py findings.jsonl security/policy.yaml security/exceptions.yaml \
      --out gate-decision.json --findings-out gated.jsonl
  report.py gated.jsonl gate-decision.json --out reports/

If plain normalize output is passed instead of the gated stream, verdicts are
merged from gate-decision.json by fingerprint (fallback).
"""
import argparse
import datetime as dt
import json
import pathlib
import re
import shutil
import sys

# --------------------------------------------------------------------------
# classification: which "result kind" a finding belongs to, and its order
# --------------------------------------------------------------------------

TOOL_KIND = {
    "gitleaks": "secrets",
    "semgrep": "sast",
    "trivy": "misconfig",  # trivy emits config/image scans; KSV/DS checks are misconfig
    "grype": "sca",
    "zap": "dast",
    "sbom": "license",
}

# section order in the report: FAIL/WARN classes first, PASS last
KIND_ORDER = ["sast", "secrets", "sca", "misconfig", "dast", "license"]

KIND_TITLES = {
    "sast": "SAST — Static Analysis (semgrep)",
    "secrets": "Secret Scanning (gitleaks)",
    "sca": "Software Composition Analysis (grype)",
    "misconfig": "Misconfiguration (trivy config/image)",
    "dast": "Dynamic Analysis (ZAP baseline)",
    "license": "License Inventory (SBOM)",
}

MAX_SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "unknown": 0}

SEV_BADGE = {
    "critical": "🔴 critical",
    "high": "🟠 high",
    "medium": "🟡 medium",
    "low": "🔵 low",
    "informational": "⚪ informational",
    "unknown": "⚪ unknown",
}


def kind_of(f: dict) -> str:
    return TOOL_KIND.get(f.get("tool", ""), "sast")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def md_escape(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")


def sev_rank(sev: str) -> int:
    return MAX_SEV.get(sev, 0)


def pct(a: int, b: int) -> float:
    return (a / b * 100) if b else 0.0


def dedupe(findings: list[dict]) -> list[dict]:
    """One entry per fingerprint *within a tool*. normalize emits one finding
    per raw artifact, so the same leak/vuln often appears 2-3× (full + repro
    scans). The first occurrence wins; later ones are absorbed as duplicates."""
    seen: set[tuple[str, str]] = set()
    out = []
    for f in findings:
        key = (f.get("tool", ""), f.get("fingerprint", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def source_link(f: dict) -> str:
    """Markdown link to the raw artifact, for browsers and for local viewing."""
    src = f.get("source") or ""
    if not src:
        return ""
    safe = src.replace("<", "%3C").replace(">", "%3E").replace(" ", "%20")
    return f"[{src}]({safe})"


def read_code_lines(path: pathlib.Path, start: int, end: int) -> str:
    """Read code lines [start, end] from a repo file, with line numbers."""
    if not path.is_file():
        return ""
    lines = path.read_text(errors="replace").splitlines()
    lines = [ln for ln in lines if not ln.startswith(("<<<<<<<", "=======", ">>>>>>>"))]
    out = []
    for n in range(max(1, start), min(end, len(lines)) + 1):
        out.append(f"{n:>4} | {lines[n - 1]}")
    return "\n".join(out)


def fmt_reason(f: dict) -> str:
    """Human verdict + why. EXCEPTED is a warning backed by an expiring
    exception — it must not read like a plain warning."""
    action = f.get("action", "pass")
    reason = f.get("reason", "")
    if action == "fail":
        return f"**FAIL** — {reason}"
    if action == "warn":
        if reason.startswith("exception"):
            return f"**EXCEPTED** — {reason}"
        return f"**WARN** — {reason}"
    return f"**PASS** — {reason}"


def finding_code_block(f: dict, code: str) -> str:
    """Collapsible <details> around the code block. HTML details is fine in
    Markdown and keeps FAIL sections terse while the vuln path stays one
    click away."""
    if not code:
        return ""
    lang = pathlib.Path(f.get("path", "")).suffix.lstrip(".") or "text"
    return "\n<details>\n<summary>source</summary>\n\n```" + lang + "\n" + code + "\n```\n</details>\n"


# --------------------------------------------------------------------------
# per-kind renderers
# --------------------------------------------------------------------------

def render_sast(findings: list[dict], repo: pathlib.Path) -> list[str]:
    """SAST: each finding = source location(s) to review the whole vuln path.

    * path normalization: SARIF URIs arrive as /src/app/app.py (semgrep) or
      src/app/app.py (gitleaks) — strip a leading /src/ so they match the
      repo layout. Used for *display only*; fingerprints never change.
    * sink = rule + snippet (the flagged line). source = where the sink is
      reached (for the demo seeds: /demo/unsafe-search → search_notes →
      unsafe_search_notes; /admin → verify_admin_password → hash_password).
      When a source cannot be traced statically we say so honestly instead of
      inventing a path.
    """
    out = ["### SAST results (semgrep)\n"]
    if not findings:
        out.append("_No gated findings._\n")
        return out

    for f in sorted(findings, key=lambda x: (-sev_rank(x.get("severity", "")), x.get("rule", ""))):
        rule = f.get("rule", "?")
        sev = SEV_BADGE.get(f.get("severity", ""), f.get("severity", "?"))
        path = (f.get("path") or "").lstrip("/").removeprefix("src/")
        line = f.get("line") or 0
        sink_code = read_code_lines(repo / path, max(1, line - 2), line + 2) if line else ""

        # source-of-sink heuristic for the seeded demo vulns; honest fallback
        source_hint = ""
        source_code = ""
        if rule in ("security.semgrep.no-formatted-sql", "security.semgrep.no-md5-hashing"):
            key = "db.unsafe_search_notes" if "sql" in rule else "verify_admin_password"
            rx = re.compile(re.escape(key))
            for p in sorted(repo.glob("app/*.py")):
                for n, ln in enumerate(p.read_text(errors="replace").splitlines(), 1):
                    if rx.search(ln):
                        source_hint = f"{p}:{n}"
                        source_code = read_code_lines(p, max(1, n - 2), n + 2)
                        break
                if source_hint:
                    break

        out.append(f"\n**{rule}** — {sev}\n")
        out.append(f"- Verdict: {fmt_reason(f)}")
        out.append(f"- Location: `{path}` line **{line}**")
        out.append(f"- Message: {md_escape(f.get('message', ''))}")
        if source_hint:
            out.append(f"- Reachable from: `{source_hint}` (source of the data flow — review the whole path, not just the sink)")
        out.append(f"- Raw artifact: {source_link(f)}")
        out.append(f"- Fingerprint: `{f.get('fingerprint', '')[:12]}…`")
        if sink_code:
            out.append(finding_code_block(f, sink_code))
            if source_hint and source_code:
                out.append("\n<details>\n<summary>data flow (source → sink)</summary>\n\n```python\n" + source_code + "\n```\n</details>\n")
    return out


def render_secrets(findings: list[dict], repo: pathlib.Path) -> list[str]:
    """Secret scanning: affected file/line + who/when (gitleaks commits).
    Gitleaks is a categorical fail tool — every row is a leak, not a risk
    debate. Show commit metadata (author, commit, date) so the reader can
    chase the history immediately."""
    out = ["### Secret scanning results (gitleaks)\n"]
    if not findings:
        out.append("_No gated findings._\n")
        return out

    out.append("| Rule | Severity | File:line | Commit | Author | Verdict |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for f in sorted(findings, key=lambda x: (x.get("path", ""), x.get("line", 0))):
        pfp = f.get("metadata", {}).get("commit")
        commit = pfp.get("commitSha", "")[:12] if isinstance(pfp, dict) else ""
        author = pfp.get("author", "") if isinstance(pfp, dict) else ""
        out.append(
            f"| {f.get('rule', '?')} | {SEV_BADGE.get(f.get('severity',''), f.get('severity','?'))} "
            f"| `{f.get('path','')}:{f.get('line',0)}` | `{commit}` | {author} | {fmt_reason(f)} |"
        )

    out.append("\n_Secrets are categorical (policy.yaml `fail_tools: [gitleaks]`): a leaked secret never passes, "
               "regardless of severity or exception._\n")
    return out


def render_sca(findings: list[dict], repo: pathlib.Path) -> list[str]:
    """SCA: package@version + vuln + CVSS/EPSS/KEV/fix + advisory links.
    Enriched by normalize.py (metadata.epss / known_exploited / fix_available)
    and by the report (CVSS from the raw grype JSON when present)."""
    out = ["### SCA results (grype)\n"]
    if not findings:
        out.append("_No gated findings._\n")
        return out

    # --- enrich from raw grype JSON first (source of truth) so the table
    #     below shows CVSS/namespace/fix — not just the lean stream. ---
    raw_dir = pathlib.Path(findings[0].get("_raw_dir", "raw"))
    advisories: dict[str, list[str]] = {}
    for f in findings:
        src = f.get("source") or ""
        raw = raw_dir / src
        if not raw.is_file() or "grype" not in src:
            continue
        try:
            data = json.loads(raw.read_text())
        except Exception:
            continue
        for m in data.get("matches", []):
            v = m.get("vulnerability", {})
            if v.get("id") != f.get("rule"):
                continue
            for url in v.get("urls", []) or []:
                advisories.setdefault(f.get("rule", ""), []).append(url)
            # namespace / cvss / fix detail from the raw record
            md = f.setdefault("metadata", {})
            md.setdefault("namespace", v.get("namespace", ""))
            if not md.get("cvss") and v.get("cvss"):
                md["cvss"] = v["cvss"]
            if not md.get("fix_available") and (m.get("fix") or v.get("fix")):
                md["fix_available"] = True

    out.append("| Package | Vuln ID | Severity | CVSS | EPSS | KEV | Fix | Verdict |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for f in sorted(findings, key=lambda x: (-sev_rank(x.get("severity", "")), x.get("path", ""))):
        md = f.get("metadata", {}) or {}
        cvss = md.get("cvss")
        if isinstance(cvss, (int, float)):
            cvss_s = f"{cvss:.1f}"
        elif isinstance(cvss, list) and cvss:
            cvss_s = "; ".join(f"v{c.get('version','?')} {c.get('metrics',{}).get('baseScore','?')}" for c in cvss)
        else:
            cvss_s = "—"
        epss = md.get("epss")
        epss_s = f"{epss:.4f}" if isinstance(epss, (int, float)) else "—"
        kev = "🚨 yes" if md.get("known_exploited") else "no"
        fix = "✅ yes" if md.get("fix_available") else "no fix"
        out.append(
            f"| `{md_escape(f.get('path',''))}` | {f.get('rule','?')} | {SEV_BADGE.get(f.get('severity',''), f.get('severity','?'))} "
            f"| {cvss_s} | {epss_s} | {kev} | {fix} | {fmt_reason(f)} |"
        )

    # advisories from the raw grype JSON (source of truth), linked per vuln
    # raw artifacts are resolved the same way as the copy loop: out/raw first,
    # then the repo's raw/ dir (they are the same files).
    if advisories:
        out.append("\n**Advisories:**\n")
        for rule, urls in advisories.items():
            links = " · ".join(f"[{u.rstrip('/').split('/')[-1]}]({u})" for u in urls)
            out.append(f"- `{rule}`: {links}")

    out.append("\n_EPSS ≥ 0.9 or known-exploited findings fail even at high severity (policy.yaml `fail_when`)._")
    out.append(f"_Raw source of truth: {source_link(findings[0])}_\n")
    return out


def render_misconfig(findings: list[dict], repo: pathlib.Path) -> list[str]:
    """Misconfig: resource (target) + check id + line + rule description.
    Trivy emits KSV-0014 & friends; custom Rego checks from security/trivy/
    show up the same way. Descriptions come from the SARIF rules table."""
    out = ["### Misconfiguration results (trivy)\n"]
    if not findings:
        out.append("_No gated findings._\n")
        return out

    # rule descriptions from raw SARIF rules tables (source of truth)
    desc: dict[str, str] = {}
    help_uri: dict[str, str] = {}
    raw_dir = pathlib.Path(findings[0].get("_raw_dir", "raw"))
    for f in findings:
        src = f.get("source") or ""
        raw = raw_dir / src
        if not raw.is_file():
            continue
        try:
            data = json.loads(raw.read_text())
        except Exception:
            continue
        for run in data.get("runs", []):
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
                rid = rule.get("id", "")
                if not rid:
                    continue
                sd = rule.get("shortDescription", {}).get("text", "")
                fd = rule.get("fullDescription", {}).get("text", "")
                desc[rid] = fd or sd or desc.get(rid, "")
                help_uri[rid] = rule.get("helpUri", "") or help_uri.get(rid, "")

    out.append("| Check | Severity | Resource | Line | Verdict |")
    out.append("| --- | --- | --- | --- | --- |")
    for f in sorted(findings, key=lambda x: (-sev_rank(x.get("severity", "")), x.get("rule", ""))):
        out.append(
            f"| {f.get('rule','?')} | {SEV_BADGE.get(f.get('severity',''), f.get('severity','?'))} "
            f"| `{md_escape(f.get('path',''))}` | {f.get('line',0) or '—'} | {fmt_reason(f)} |"
        )

    out.append("\n**Check details:**\n")
    for f in sorted(findings, key=lambda x: x.get("rule", "")):
        rule = f.get("rule", "?")
        d = desc.get(rule, "")
        uri = help_uri.get(rule, "")
        line = f"`{f.get('path','')}`:{f.get('line',0)}" if f.get("line") else f"`{f.get('path','')}`"
        code = read_code_lines(repo / (f.get("path") or ""), max(1, (f.get("line") or 1) - 3), (f.get("line") or 1) + 3)
        out.append(f"\n**{rule}**")
        if d:
            out.append(f"> {md_escape(d)}")
        out.append(f"- Location: {line} · Verdict: {fmt_reason(f)}")
        if uri:
            out.append(f"- Reference: {uri}")
        if code:
            out.append(finding_code_block(f, code))

    out.append("\n_Descriptions resolved from the trivy SARIF rules table (raw/)._\n")
    return out


def render_dast(findings: list[dict], repo: pathlib.Path) -> list[str]:
    """DAST (ZAP): URL + alert + evidence. Lowest detail — ZAP's normalized
    stream is already the full story for a URL scan."""
    out = ["### DAST results (ZAP baseline)\n"]
    if not findings:
        out.append("_No gated findings._\n")
        return out

    out.append("| Alert | Severity | URL | CWE | Verdict |")
    out.append("| --- | --- | --- | --- | --- |")
    for f in sorted(findings, key=lambda x: (-sev_rank(x.get("severity", "")), x.get("path", ""))):
        cwe = (f.get("metadata", {}) or {}).get("cwe", "")
        out.append(
            f"| {md_escape(f.get('rule','?'))} | {SEV_BADGE.get(f.get('severity',''), f.get('severity','?'))} "
            f"| `{md_escape(f.get('path',''))}` | {cwe or '—'} | {fmt_reason(f)} |"
        )
    out.append(f"\n_Raw source of truth: {source_link(findings[0])}_\n")
    return out


def render_license(findings: list[dict], repo: pathlib.Path) -> list[str]:
    """License inventory: component + licenses, grouped blocked/review/info
    per policy.yaml licenses.{fail,warn}."""
    out = ["### License inventory (SBOM)\n"]
    if not findings:
        out.append("_No gated findings._\n")
        return out

    rows = []
    for f in findings:
        lic = (f.get("metadata", {}) or {}).get("licenses", []) or []
        rows.append((f.get("path", ""), sorted(lic), f))
    rows.sort(key=lambda r: r[0].lower())

    blocked, review, info = [], [], []
    for comp, lic, f in rows:
        if any(lc in (f.get("_blocked", []) or []) for lc in lic):
            blocked.append((comp, lic))
        elif any(lc in (f.get("_warn", []) or []) for lc in lic):
            review.append((comp, lic))
        else:
            info.append((comp, lic))

    def table(rows_):
        out_ = ["| Component | Licenses |", "| --- | --- |"]
        out_ += [f"| `{md_escape(c)}` | {', '.join(sorted(set(ls)))} |" for c, ls in rows_]
        return out_

    if blocked:
        out.append(f"\n**Blocked ({len(blocked)}):**\n")
        out += table(blocked)
    if review:
        out.append(f"\n**Require review ({len(review)}):**\n")
        out += table(review)
    if info:
        out.append(f"\n**Informational ({len(info)}):**\n")
        out += table(info)

    out.append("\n_Policy: `licenses.warn` list from security/policy.yaml._\n")
    return out


# --------------------------------------------------------------------------
# policy summary
# --------------------------------------------------------------------------

def render_policy(policy: dict) -> list[str]:
    sev = policy.get("severity_defaults", {})
    rows = " · ".join(f"{k}={v}" for k, v in sev.items())
    fail_rules = ", ".join(policy.get("fail_rule_classes", [])) or "—"
    fail_tools = ", ".join(policy.get("fail_tools", [])) or "—"
    fw = []
    for c in policy.get("fail_when", []):
        if c.get("field") == "known_exploited":
            fw.append(f"known-exploited ({', '.join(c.get('severities', []))})")
        elif c.get("field") == "epss":
            fw.append(f"EPSS ≥ {c.get('value')} ({', '.join(c.get('severities', []))})")
    fw_s = ", ".join(fw) or "—"
    lic = policy.get("licenses", {})
    return [
        "### Policy applied (security/policy.yaml)\n",
        f"- Severity defaults: {rows}",
        f"- Exploitability classes (fail): {fail_rules}",
        f"- Categorical tools (fail): {fail_tools}",
        f"- KEV/EPSS overrides: {fw_s}",
        f"- Exceptions: max severity {policy.get('exceptions', {}).get('max_severity', 'high')}",
        f"- Licenses — warn: {', '.join(lic.get('warn', [])) or '—'} · fail: {', '.join(lic.get('fail', [])) or '—'}",
        "",
    ]


def render_exceptions(exc: list[dict]) -> list[str]:
    if not exc:
        return []
    # one row per exception ID (a finding may be duplicated across artifacts;
    # the exception itself is a single approval)
    seen: set[str] = set()
    rows = []
    for e in exc:
        eid = e.get("exc_id", e.get("id", ""))
        if eid in seen:
            continue
        seen.add(eid)
        rows.append(f"| {eid} | {e.get('rule','')} | `{e.get('path','')}` | {e.get('expires','')} | {e.get('approved_by','')} |")
    out = ["### Exceptions applied\n", "| ID | Rule | Path | Expires | Approved by |", "| --- | --- | --- | --- | --- |"] + rows
    out.append("\n_Exact-fingerprint, expiring (security/exceptions.yaml). Expired exceptions block the build._\n")
    return out


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("findings", help="findings.jsonl (GATED — gate.py --findings-out; falls back to raw normalize output)")
    ap.add_argument("decision", help="gate-decision.json from gate.py")
    ap.add_argument("--out", required=True, help="output DIRECTORY (report.md + raw/ go here)")
    ap.add_argument("--repo", default=".", help="repo root for reading source files (default: cwd)")
    ap.add_argument("--audit", default="audit/exceptions-audit.jsonl", help="exception audit trail from gate.py (optional)")
    args = ap.parse_args()

    out_dir = pathlib.Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    repo = pathlib.Path(args.repo)

    findings = [json.loads(ln) for ln in pathlib.Path(args.findings).read_text().splitlines() if ln.strip()]
    decision = json.loads(pathlib.Path(args.decision).read_text())

    # --- fallback: raw normalize output has no action/reason — merge the
    #     gate's decision lists by fingerprint so verdicts still render. ---
    if findings and "action" not in findings[0]:
        act: dict[str, str] = {}
        rs: dict[str, str] = {}
        for grp in (decision.get("failures", []), decision.get("warnings", [])):
            for e in grp:
                fp = e.get("fingerprint")
                if fp:
                    act[fp] = "fail" if grp is decision.get("failures", []) else "warn"
                    rs[fp] = e.get("reason", "")
        for f in findings:
            fp = f.get("fingerprint", "")
            if fp in act:
                f["action"] = act[fp]
                f["reason"] = rs[fp]
            else:
                f["action"] = "pass"
                f["reason"] = "severity not gated (no failure/warning)"

    # --- copy raw artifacts next to the report (self-contained dir) ---
    # Lookup order: path as-is (absolute), repo/raw/<name>, findings-dir-relative.
    findings_path = pathlib.Path(args.findings)
    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    copied: set[str] = set()
    warned: set[str] = set()
    for f in findings:
        src = f.get("source") or ""
        if not src or src in copied:
            continue
        p = pathlib.Path(src)
        cand = next(
            (c for c in (p, repo / "raw" / p, findings_path.parent / p, findings_path.parent / "raw" / p) if c.is_file()),
            None,
        )
        if cand:
            shutil.copy2(cand, raw_dir / p.name)
            copied.add(src)
        elif src not in warned:
            print(f"report: WARN raw artifact not found for {src}", file=sys.stderr)
            warned.add(src)

    for f in findings:
        f["_raw_dir"] = str(raw_dir)

    # --- enrich: gitleaks commit metadata from raw SARIF (partialFingerprints) ---
    # Only fills gaps; normalize.py already captures it for new runs.
    for f in findings:
        md = f.get("metadata", {}) or {}
        if f.get("tool") == "gitleaks" and not md.get("commit"):
            raw = raw_dir / (f.get("source") or "")
            if raw.is_file():
                try:
                    data = json.loads(raw.read_text())
                    for run in data.get("runs", []):
                        for res in run.get("results", []):
                            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
                            if loc.get("artifactLocation", {}).get("uri") == f.get("path") \
                               and (loc.get("region") or {}).get("startLine") == f.get("line"):
                                pfp = res.get("partialFingerprints") or {}
                                if isinstance(pfp, dict) and pfp:
                                    md["commit"] = pfp
                                    f["metadata"] = md
                                break
                except Exception:
                    pass
    # --- exceptions (matched by fingerprint from the audit trail) ---
    exc_by_fp: dict[str, dict] = {}
    audit = pathlib.Path(args.audit)
    if audit.is_file():
        for ln in audit.read_text().splitlines():
            if not ln.strip():
                continue
            try:
                e = json.loads(ln)
            except Exception:
                continue
            if e.get("event") == "EXCEPTION_APPLIED":
                exc_by_fp[e["fingerprint"]] = e

    for f in findings:
        exc = exc_by_fp.get(f.get("fingerprint", ""))
        if exc:
            exc = dict(exc)  # copy — audit entries are shared across findings
            exc.setdefault("path", f.get("path", ""))
            f["_exc"] = exc
            f["_blocked"] = exc.get("_blocked", []) or []
            f["_warn"] = exc.get("_warn", []) or []

    # --- group by kind, dedupe within tool ---
    by_kind: dict[str, list[dict]] = {k: [] for k in KIND_ORDER}
    for f in findings:
        if f.get("tool") == "sbom":
            continue
        by_kind[kind_of(f)].append(f)
    for k in by_kind:
        by_kind[k] = dedupe(by_kind[k])
    licenses = dedupe([f for f in findings if f.get("tool") == "sbom"])
    counts = decision.get("counts", {})
    n_fail = counts.get("fail", 0)
    n_warn = counts.get("warn", 0)
    n_pass = counts.get("pass", 0)
    n_total = counts.get("total", len(findings))
    n_uniq = sum(len(v) for v in by_kind.values()) + len(licenses)

    status = decision.get("status", "pass")
    badge = {
        "fail": "❌ GATE FAILED",
        "pass": "✅ GATE PASSED",
        "warn": "⚠️ GATE WARN — review warnings",
        "error": "⛔ GATE ERROR — could not evaluate",
    }.get(status, status.upper())
    # license policy — same file the gate read (security/policy.yaml)
    import yaml
    lic_warn: set[str] = set()
    lic_fail: set[str] = set()
    try:
        pol = yaml.safe_load((repo / "security" / "policy.yaml").read_text())
        lic_warn = set(pol.get("licenses", {}).get("warn", []))
        lic_fail = set(pol.get("licenses", {}).get("fail", []))
    except Exception:
        pass

    lines: list[str] = []
    lines.append(f"# Security Gate Report — {status.upper()}")
    lines.append("")
    lines.append(f"_Generated {dt.datetime.now().strftime('%Y-%m-%d %H:%M %Z')} by tools/report.py · "
                 f"{n_uniq} unique gated findings (deduped within tool) from {n_total} normalized findings_")
    lines.append("")
    lines.append(f"## {badge} — {n_fail} fail · {n_warn} warn · {n_pass} pass")
    lines.append("")
    lines += render_policy(policy_dict(policy_path=repo / "security" / "policy.yaml"))
    lines.append("---")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    for kind in KIND_ORDER:
        f = by_kind.get(kind, [])
        has_fail = any(x.get("action") == "fail" for x in f)
        if not f:
            continue
        anchor = f"### {KIND_TITLES[kind]}" + (" — ❌ blocking" if has_fail else "")
        lines.append(anchor)
        lines.append("")
        lines += {
            "sast": render_sast,
            "secrets": render_secrets,
            "sca": render_sca,
            "misconfig": render_misconfig,
            "dast": render_dast,
        }[kind](f, repo)
        lines.append("---")
        lines.append("")

    if licenses:
        lines.append(f"### {KIND_TITLES['license']}")
        lines.append("")
        for f in licenses:
            f["_warn"] = sorted(set((f.get("metadata", {}) or {}).get("licenses", [])) & lic_warn)
            f["_blocked"] = sorted(set((f.get("metadata", {}) or {}).get("licenses", [])) & lic_fail)
        lines += render_license(licenses, repo)
        lines.append("---")
        lines.append("")

    applied = [f["_exc"] for f in findings if "_exc" in f]
    if applied:
        lines += render_exceptions(applied)
        lines.append("---")
        lines.append("")

    lines.append("## Raw artifacts")
    lines.append("")
    lines.append("Full scanner outputs are copied to `raw/` next to this report — the source of truth behind every row above.")
    lines.append("")

    report_path = out_dir / "report.md"
    report_path.write_text("\n".join(lines))
    print(f"report: {n_uniq} unique findings -> {report_path}")
    print(f"report: raw artifacts -> {raw_dir}/")
    return 0


def policy_dict(policy_path: pathlib.Path) -> dict:
    import yaml
    try:
        return yaml.safe_load(policy_path.read_text()) or {}
    except Exception:
        return {}


if __name__ == "__main__":
    sys.exit(main())
