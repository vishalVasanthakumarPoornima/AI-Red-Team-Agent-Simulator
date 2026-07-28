# Canonical report schema

`redteam_platform.reporting.models.CanonicalReport` is the only model consumed
by renderers. Nested Pydantic objects remain structured in JSON.

The model includes document control, run timing and status, target and
authorization summaries, inventory and components, plan/probe/adaptive/Kali
statistics, typed findings and evidence references, coverage, non-pass
outcomes, deterministic remediation, retest state, integrity, tools, model
roles, stop reason, appendices, and typed reporting warnings.

Finding fingerprints are SHA-256 digests of normalized target, category,
component, and title identity. Finding status supports open, confirmed,
likely, informational, accepted risk, mitigated, resolved, false positive, and
not retested. False positives require an explicit rationale.

Risk is a transparent qualitative ordinal from 0-4 based on displayed inputs:
technical severity, confidence, exploitability, exposure, privileges, user
interaction, business impact, data sensitivity, and control effectiveness.
It is not an official CVSS score. CVSS vector and score fields remain empty
unless sufficient metrics are supplied together.

Standards mappings are versioned structured records based on registered
finding categories, with rationale. They do not imply certification.
