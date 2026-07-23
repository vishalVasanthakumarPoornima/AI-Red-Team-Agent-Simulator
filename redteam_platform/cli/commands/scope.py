"""Scope-policy inspection without assessment side effects."""

from __future__ import annotations

import typer

from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.formatting import details_table, emit_envelope, title
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy


def register(root: typer.Typer, scope_app: typer.Typer) -> None:
    root.add_typer(scope_app, name="scope")

    @scope_app.command("show", help="Show effective scope rules. Passive and offline.")
    def scope_show(ctx: typer.Context, json_output: bool = typer.Option(False, "--json")) -> None:
        state: CLIContext = ctx.find_root().obj
        settings = state.settings
        data = {
            "default_policy": "deny unless loopback or explicitly configured lab target",
            "allowed_cidrs": settings.allowed_cidrs,
            "allowed_domains": settings.allowed_domains,
            "public_targets_enabled": settings.allow_public,
            "configured_kali_aliases": settings.allowed_kali_aliases,
            "sensitive_destination_blocks": [
                "cloud metadata",
                "broadcast",
                "multicast",
                "link-local",
                "unspecified",
            ],
            "active_assessment_requires_authorization": True,
        }
        if state.json_output or json_output:
            emit_envelope(state, "scope.show", data)
        else:
            title(state, "Scope and authorization", "Inspection only; no target is contacted")
            state.console.print(details_table("Effective policy", data.items()))

    def decide(state: CLIContext, target: str) -> dict:
        original = target
        try:
            decision = ScopePolicy(state.settings).decide(target, active=False)
            payload = {
                "original_target": original,
                "normalized_target": decision.normalized_target,
                "target_type": decision.evidence.get("scheme", "unknown"),
                "classification": decision.classification,
                "allowed": decision.allowed,
                "policy_rule": decision.policy_rule,
                "reason": decision.reason,
                "dns_evidence": decision.resolved_addresses,
                "resolution_errors": [],
            }
        except ScopeDeniedError as exc:
            payload = {
                "original_target": original,
                "normalized_target": None,
                "target_type": "unknown",
                "classification": "blocked",
                "allowed": False,
                "policy_rule": "parse-or-resolution-denied",
                "reason": str(exc),
                "dns_evidence": [],
                "resolution_errors": [str(exc)],
            }
        return payload

    @scope_app.command("validate", help="Normalize and validate a target. Passive; never executes assessment tools.")
    def scope_validate(
        ctx: typer.Context,
        target: str,
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state: CLIContext = ctx.find_root().obj
        payload = decide(state, target)
        if state.json_output or json_output:
            emit_envelope(state, "scope.validate", payload, success=payload["allowed"])
        else:
            title(state, "Target scope decision", "No assessment activity was performed")
            state.console.print(details_table("Decision", payload.items()))
        if not payload["allowed"]:
            raise SystemExit(4)

    @scope_app.command("explain", help="Explain the applicable target rules in plain language. Passive.")
    def scope_explain(
        ctx: typer.Context,
        target: str,
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state: CLIContext = ctx.find_root().obj
        payload = decide(state, target)
        explanation = (
            f"The target normalizes to {payload['normalized_target']}. "
            f"It is classified as {payload['classification']} under rule "
            f"{payload['policy_rule']}. {payload['reason']} "
            "Active testing additionally requires a human authorization statement "
            "and a final confirmation; --yes cannot supply authorization."
        )
        data = {**payload, "explanation": explanation}
        if state.json_output or json_output:
            emit_envelope(state, "scope.explain", data, success=payload["allowed"])
        else:
            title(state, "Scope explanation")
            state.console.print(explanation)
