"""Accessible, self-contained HTML renderer without remote dependencies."""

from __future__ import annotations

import html
from collections import Counter

from redteam_platform.reporting.models import CanonicalReport


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


class HtmlRenderer:
    media_type = "text/html"
    suffix = ".html"

    def render(self, report: CanonicalReport) -> str:
        counts = Counter(item.severity for item in report.findings)
        maximum = max([1, *counts.values()])
        severity_chart = "".join(
            (
                f"<li><span>{_esc(severity.title())}</span>"
                f"<span class='bar'><span style='width:{counts.get(severity, 0) / maximum * 100:.0f}%'></span></span>"
                f"<strong>{counts.get(severity, 0)}</strong></li>"
            )
            for severity in ("critical", "high", "medium", "low", "informational")
        )
        coverage_rows = "".join(
            "<tr>"
            f"<th scope='row'>{_esc(item.category)}</th><td>{_esc(item.state)}</td>"
            f"<td>{item.completed}/{item.planned}</td><td>{item.percentage:.1f}%</td>"
            "</tr>"
            for item in report.coverage.categories
        )
        finding_cards = "".join(
            (
                f"<article class='finding severity-{_esc(item.severity)}' id='finding-{_esc(item.finding_id)}'>"
                f"<h3>{_esc(item.finding_id)}: {_esc(item.title)}</h3>"
                f"<p><span class='badge'>{_esc(item.severity)}</span> "
                f"{_esc(item.confidence)} confidence · {_esc(item.status)}</p>"
                f"<dl><dt>Category</dt><dd>{_esc(item.category)}</dd>"
                f"<dt>Component</dt><dd>{_esc(item.affected_component or 'target-wide')}</dd>"
                f"<dt>Risk</dt><dd>{_esc(item.risk.rating)} — qualitative {item.risk.ordinal}/4</dd></dl>"
                f"<p>{_esc(item.description or item.technical_details)}</p>"
                f"<h4>Impact</h4><p>{_esc(item.impact)}</p>"
                f"<h4>Remediation</h4><p>{_esc(item.remediation)}</p>"
                f"<details><summary>Evidence and validation detail</summary>"
                f"<p>{_esc(item.evidence_summary or 'See referenced run evidence.')}</p>"
                f"<pre>{_esc(item.reproduction_guidance)}</pre></details></article>"
            )
            for item in report.findings
        ) or "<p>No findings were recorded by completed probes.</p>"
        remediation = "".join(
            f"<li><strong>{_esc(item.priority.replace('_', ' ').title())}:</strong> "
            f"{_esc(item.title)} — {_esc(item.rationale)}</li>"
            for item in report.recommendations
        )
        evidence_rows = "".join(
            "<li><code>"
            f"{_esc(item.evidence_id)}</code> · probe <code>{_esc(item.source_probe or 'unknown')}</code> "
            f"· {_esc(item.description or item.evidence_type)} · hash "
            f"<code>{_esc(item.content_hash or 'not recorded')}</code></li>"
            for item in report.evidence_references[:50]
        ) or "<li>No structured evidence references were retained.</li>"
        summary = "".join(f"<li>{_esc(item)}</li>" for item in report.executive_summary)
        methodology = "".join(f"<li>{_esc(item)}</li>" for item in report.methodology)
        components = "".join(
            "<tr>"
            f"<th scope='row'>{_esc(item.get('name') or item.get('stable_id') or 'component')}</th>"
            f"<td>{_esc(item.get('component_type') or 'unknown')}</td>"
            f"<td>{_esc(item.get('status') or 'unknown')}</td></tr>"
            for item in report.target.components
        )
        kali_section = (
            "<section class='panel'><h2>Kali-assisted results</h2>"
            f"<p>Completed {report.kali.checks_completed} bounded check(s); "
            f"skipped {report.kali.checks_skipped}; tunnel used: {_esc(report.kali.tunnel_used)}.</p>"
            f"<p>Available tools: {_esc(', '.join(report.kali.tools_available) or 'none recorded')}.</p></section>"
            if report.kali.configured or report.kali.used else ""
        )
        adaptive_section = (
            "<section class='panel'><h2>Adaptive assessment activity</h2>"
            f"<p>Mode {_esc(report.adaptive_mode)}; {report.adaptive_statistics.rounds_completed} round(s), "
            f"{report.adaptive_statistics.model_calls} model call(s), "
            f"{report.adaptive_statistics.proposals_accepted} accepted and "
            f"{report.adaptive_statistics.proposals_rejected} rejected proposal(s).</p></section>"
            if report.adaptive_mode != "off" else ""
        )
        nonpass = "".join(
            f"<li>{_esc(kind)}: {_esc(item)}</li>"
            for kind, values in (
                ("Error", report.errors),
                ("Timeout", report.timeouts),
                ("Unavailable", report.unavailable_capabilities),
                ("Skipped", report.skipped_tests),
            )
            for item in values
        )
        nonpass_section = (
            f"<section class='panel'><h2>Errors, timeouts, and unavailable tests</h2><ul>{nonpass}</ul></section>"
            if nonpass else ""
        )
        banner = (
            "SAFE-SHARE REPORT — personal and machine-specific details are aliased."
            if report.mode == "safe_share"
            else "INTERNAL REPORT — authorized technical detail; secrets remain redacted."
        )
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_esc(report.branding.report_title)}</title>
<style>
:root{{--accent:#173b63;--critical:#8b1e2d;--high:#b44b22;--medium:#a16b00;--low:#33658a;--info:#52606d}}
*{{box-sizing:border-box}}body{{margin:0;color:#17212b;background:#f5f7fa;font:16px/1.55 system-ui,sans-serif}}
a{{color:#124e78}}aside{{position:fixed;width:17rem;height:100vh;padding:1.5rem;background:#102a43;color:white}}
aside a{{display:block;color:#d9eaf7;padding:.35rem 0}}main{{max-width:74rem;margin-left:17rem;padding:2rem 3rem}}
header,.panel,.finding{{background:white;border:1px solid #d9e2ec;border-radius:.5rem;padding:1.5rem;margin-bottom:1.25rem}}
.banner{{padding:.75rem;background:#fff3bf;border-left:.4rem solid #e6a700}}table{{width:100%;border-collapse:collapse}}
th,td{{padding:.55rem;border-bottom:1px solid #d9e2ec;text-align:left}}.badge{{color:white;background:var(--accent);padding:.2rem .5rem;border-radius:1rem}}
.severity-critical .badge{{background:var(--critical)}}.severity-high .badge{{background:var(--high)}}
.severity-medium .badge{{background:var(--medium)}}.severity-low .badge{{background:var(--low)}}.severity-informational .badge{{background:var(--info)}}
.chart{{padding:0;list-style:none}}.chart li{{display:grid;grid-template-columns:7rem 1fr 2rem;gap:.6rem;align-items:center}}
.bar{{height:.75rem;background:#e6edf3}}.bar span{{display:block;height:100%;background:var(--accent)}}
dt{{font-weight:700}}dd{{margin:0 0 .5rem}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}:focus{{outline:3px solid #f0b429}}
@media(max-width:800px){{aside{{position:static;width:auto;height:auto}}main{{margin:0;padding:1rem}}}}
@media print{{aside{{display:none}}main{{margin:0;padding:0}}body{{background:white}}.panel,.finding,header{{break-inside:avoid;border-color:#aaa}}details{{display:block}}}}
</style></head><body>
<aside aria-label="Report navigation"><h2>Contents</h2>
<a href="#summary">Executive summary</a><a href="#scope">Scope</a>
<a href="#findings">Findings</a><a href="#coverage">Coverage</a>
<a href="#remediation">Remediation</a><a href="#integrity">Integrity</a></aside>
<main><header><p class="banner" role="note">{_esc(banner)}</p>
<h1>{_esc(report.branding.report_title)}</h1>
<p>{_esc(report.target.name)} · Run <code>{_esc(report.run_id)}</code></p>
<p>Classification: {_esc(report.branding.classification_label)} · Generated {_esc(report.generated_at.isoformat())}</p></header>
<section class="panel"><h2>Document control</h2><dl>
<dt>Report ID</dt><dd>{_esc(report.report_id)}</dd><dt>Schema</dt><dd>{_esc(report.schema_version)}</dd>
<dt>Mode</dt><dd>{_esc(report.mode)}</dd><dt>Owner</dt><dd>{_esc(report.branding.assessment_owner)}</dd></dl></section>
<section class="panel" id="summary"><h2>Executive summary</h2><ul>{summary}</ul></section>
<section class="panel" id="scope"><h2>Scope and authorization</h2>
<dl><dt>Scope</dt><dd>{_esc(report.authorization.scope)}</dd>
<dt>Classification</dt><dd>{_esc(report.authorization.scope_classification)}</dd>
<dt>Profile</dt><dd>{_esc(report.profile)}</dd><dt>Status</dt><dd>{_esc(report.assessment_status)}</dd></dl></section>
<section class="panel"><h2>Target overview</h2><dl>
<dt>Stable ID</dt><dd>{_esc(report.target.target_id)}</dd><dt>Type</dt><dd>{_esc(report.target.target_type)}</dd>
<dt>Endpoint</dt><dd>{_esc(report.target.endpoint or 'not recorded')}</dd>
<dt>Reachable</dt><dd>{_esc(report.target.reachable if report.target.reachable is not None else 'unverified')}</dd></dl></section>
{("<section class='panel'><h2>Architecture and component summary</h2><table><thead><tr><th>Component</th><th>Type</th><th>Status</th></tr></thead><tbody>" + components + "</tbody></table></section>") if components else ""}
<section class="panel"><h2>Methodology and safety controls</h2><ul>{methodology}</ul>
<p>Only exact authorized targets and registered bounded probes were used. Non-pass outcomes remain visible.</p></section>
<section class="panel" aria-labelledby="severity-title"><h2 id="severity-title">Findings by severity</h2>
<ul class="chart" role="img" aria-label="Findings by severity: {_esc(dict(counts))}">{severity_chart}</ul></section>
<section id="findings"><h2>Detailed findings</h2>{finding_cards}</section>
{kali_section}{adaptive_section}
<section class="panel" id="coverage"><h2>Coverage analysis</h2>
<p>Overall coverage: <strong>{report.coverage.overall_percentage:.1f}%</strong>. {_esc(report.coverage.denominator_explanation)}</p>
<table><thead><tr><th scope="col">Category</th><th scope="col">State</th><th scope="col">Completed</th><th scope="col">Coverage</th></tr></thead>
<tbody>{coverage_rows}</tbody></table></section>
{nonpass_section}
<section class="panel"><h2>Risk analysis</h2><p>Ratings are transparent qualitative ordinals from displayed inputs. No official CVSS score is claimed without complete metrics.</p></section>
<section class="panel" id="remediation"><h2>Prioritized remediation plan</h2><ol>{remediation}</ol></section>
<section class="panel"><h2>Retest guidance</h2><p>Repeat the same registered probes after remediation and compare stable fingerprints. Skipped, unavailable, errored, and timed-out probes cannot resolve findings.</p></section>
<section class="panel" id="integrity"><h2>Artifact and evidence integrity</h2>
<p>Status: <strong>{_esc(report.integrity.status)}</strong>; verified {report.integrity.hashes_verified}/{report.integrity.files_checked} hashes.</p>
<details><summary>Evidence references</summary><ul>{evidence_rows}</ul></details></section>
<section class="panel"><h2>Limitations</h2><p>This report provides bounded security-assessment evidence and does not provide compliance certification. Absence of a finding does not prove absence of a vulnerability.</p></section>
<footer>{_esc(report.branding.footer_text)}</footer></main></body></html>
"""
