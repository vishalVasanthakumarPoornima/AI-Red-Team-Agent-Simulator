"""Phase 6 adaptive lifecycle CLI."""

from __future__ import annotations

from typing import Optional

import typer

from redteam_platform.adaptive_engine.models import AdaptiveMode, ModelRole
from redteam_platform.adaptive_engine.service import AdaptiveAssessmentService
from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.formatting import data_table, details_table, emit_envelope
from redteam_platform.cli.progress import operation
from redteam_platform.schemas import AssessmentProfile
from redteam_platform.targets.models import TargetKind


KIND_HINTS = {
    "python": TargetKind.PYTHON_AGENT,
    "agent": TargetKind.HTTP_AGENT,
    "http": TargetKind.HTTP_AGENT,
    "openai": TargetKind.OPENAI_COMPATIBLE,
    "ollama": TargetKind.OLLAMA_ENDPOINT,
    "dexter": TargetKind.DEXTER,
}


def _state(ctx: typer.Context) -> CLIContext:
    return ctx.find_root().obj


def _roles(
    planner_model: str | None,
    mutator_model: str | None,
    summarizer_model: str | None,
    reviewer_model: str | None,
) -> dict[str, str]:
    return {
        str(role): value
        for role, value in (
            (ModelRole.PLANNER, planner_model),
            (ModelRole.MUTATOR, mutator_model),
            (ModelRole.SUMMARIZER, summarizer_model),
            (ModelRole.REVIEWER, reviewer_model),
        )
        if value
    }


def _budget(
    max_rounds,
    max_total_probes,
    max_probes_per_round,
    max_model_calls,
    max_duration,
):
    return {
        key: value
        for key, value in {
            "max_rounds": max_rounds,
            "max_total_probes": max_total_probes,
            "max_probes_per_round": max_probes_per_round,
            "max_model_calls": max_model_calls,
            "max_duration_seconds": max_duration,
        }.items()
        if value is not None
    }


def register(root: typer.Typer, adaptive_app: typer.Typer) -> None:
    root.add_typer(adaptive_app, name="adaptive")

    @adaptive_app.callback(invoke_without_command=True)
    def adaptive_root(ctx: typer.Context):
        if ctx.invoked_subcommand is None:
            state = _state(ctx)
            state.console.print(ctx.get_help())

    @adaptive_app.command("status", help="Show adaptive modes, guardrails, and default budgets.")
    def status(
        ctx: typer.Context,
        json_output: bool = typer.Option(False, "--json"),
    ):
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        payload = AdaptiveAssessmentService(state.settings).status()
        if state.json_output:
            emit_envelope(state, "adaptive.status", payload)
        else:
            state.console.print(details_table("Adaptive status", payload.items()))

    @adaptive_app.command("models", help="List scoped local model candidates without changing them.")
    def models(
        ctx: typer.Context,
        live: bool = typer.Option(False, "--live", help="Opt into bounded live Ollama discovery."),
        json_output: bool = typer.Option(False, "--json"),
    ):
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        rows = AdaptiveAssessmentService(state.settings).models(live=live)
        if state.json_output:
            emit_envelope(state, "adaptive.models", rows)
        else:
            state.console.print(
                data_table(
                    "Adaptive model candidates",
                    ["Model", "Provider", "Installed", "Running", "Size", "Context", "Eligible"],
                    [
                        (
                            row.model,
                            row.provider,
                            row.installed,
                            row.running,
                            row.size_bytes,
                            row.context_length,
                            row.policy_eligible,
                        )
                        for row in rows
                    ],
                )
            )

    @adaptive_app.command("plan", help="Plan bounded adaptive coverage without creating a run.")
    def plan(
        ctx: typer.Context,
        target: str = typer.Argument(..., metavar="TARGET"),
        kind: str = typer.Option("python", "--kind"),
        profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD, "--profile"),
        mode: AdaptiveMode = typer.Option(AdaptiveMode.GUIDED, "--adaptive-mode"),
        target_model: Optional[str] = typer.Option(None, "--target-model"),
        planner_model: Optional[str] = typer.Option(None, "--planner-model"),
        mutator_model: Optional[str] = typer.Option(None, "--mutator-model"),
        summarizer_model: Optional[str] = typer.Option(None, "--summarizer-model"),
        reviewer_model: Optional[str] = typer.Option(None, "--reviewer-model"),
        fallback_model: Optional[str] = typer.Option(None, "--fallback-model"),
        allow_fallback: bool = typer.Option(False, "--allow-fallback"),
        max_rounds: Optional[int] = typer.Option(None, "--max-rounds", min=1, max=32),
        max_total_probes: Optional[int] = typer.Option(None, "--max-total-probes", min=1, max=500),
        max_probes_per_round: Optional[int] = typer.Option(None, "--max-probes-per-round", min=1, max=50),
        max_model_calls: Optional[int] = typer.Option(None, "--max-model-calls", min=0, max=200),
        max_duration: Optional[int] = typer.Option(None, "--max-duration", min=1, max=7200),
        include_kali: bool = typer.Option(False, "--include-kali", help="Include the registered bounded Kali adapter in a Dexter baseline."),
        json_output: bool = typer.Option(False, "--json"),
    ):
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        payload = AdaptiveAssessmentService(state.settings).plan(
            target,
            mode=mode,
            profile=profile,
            kind_hint=KIND_HINTS.get(kind),
            target_model=target_model,
            role_models=_roles(planner_model, mutator_model, summarizer_model, reviewer_model),
            fallback_model=fallback_model,
            allow_fallback=allow_fallback,
            budget_overrides=_budget(max_rounds, max_total_probes, max_probes_per_round, max_model_calls, max_duration),
            include_kali=include_kali,
        )
        if state.json_output:
            emit_envelope(state, "adaptive.plan", payload)
        else:
            state.console.print(details_table("Adaptive target", payload["target"].model_dump(mode="json").items()))
            state.console.print(details_table("Adaptive configuration", payload["configuration"].model_dump(mode="json").items()))
            state.console.print(
                data_table(
                    "Round-one proposals",
                    ["Proposal", "Hypothesis", "Template", "Category", "Requests"],
                    [
                        (
                            row.proposal_id,
                            row.hypothesis_id,
                            row.template_id,
                            row.category,
                            row.request_count,
                        )
                        for row in payload["proposals"]
                    ],
                )
            )

    @adaptive_app.command("run", help="Run a confirmed Phase 5 baseline plus bounded adaptive rounds.")
    def run(
        ctx: typer.Context,
        target: str = typer.Argument(..., metavar="TARGET"),
        authorization: str = typer.Option(..., "--authorization"),
        kind: str = typer.Option("python", "--kind"),
        profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD, "--profile"),
        mode: AdaptiveMode = typer.Option(AdaptiveMode.GUIDED, "--adaptive-mode"),
        target_model: Optional[str] = typer.Option(None, "--target-model"),
        planner_model: Optional[str] = typer.Option(None, "--planner-model"),
        mutator_model: Optional[str] = typer.Option(None, "--mutator-model"),
        summarizer_model: Optional[str] = typer.Option(None, "--summarizer-model"),
        reviewer_model: Optional[str] = typer.Option(None, "--reviewer-model"),
        fallback_model: Optional[str] = typer.Option(None, "--fallback-model"),
        allow_fallback: bool = typer.Option(False, "--allow-fallback"),
        max_rounds: Optional[int] = typer.Option(None, "--max-rounds", min=1, max=32),
        max_total_probes: Optional[int] = typer.Option(None, "--max-total-probes", min=1, max=500),
        max_probes_per_round: Optional[int] = typer.Option(None, "--max-probes-per-round", min=1, max=50),
        max_model_calls: Optional[int] = typer.Option(None, "--max-model-calls", min=0, max=200),
        max_duration: Optional[int] = typer.Option(None, "--max-duration", min=1, max=7200),
        include_kali: bool = typer.Option(False, "--include-kali", help="Include the registered bounded Kali adapter in a Dexter baseline."),
        json_output: bool = typer.Option(False, "--json"),
    ):
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        if state.assume_yes:
            raise ValueError("--yes cannot enable or confirm adaptive or deep-lab execution.")
        with operation(state, "Running bounded adaptive assessment…"):
            payload = AdaptiveAssessmentService(state.settings).run(
                target,
                authorization=authorization,
                mode=mode,
                profile=profile,
                kind_hint=KIND_HINTS.get(kind),
                target_model=target_model,
                role_models=_roles(planner_model, mutator_model, summarizer_model, reviewer_model),
                fallback_model=fallback_model,
                allow_fallback=allow_fallback,
                budget_overrides=_budget(max_rounds, max_total_probes, max_probes_per_round, max_model_calls, max_duration),
                interactive_confirmation=state.interactive,
                include_kali=include_kali,
            )
        if state.json_output:
            emit_envelope(state, "adaptive.run", payload)
        else:
            state.console.print(details_table("Adaptive summary", payload["summary"].model_dump(mode="json").items()))
            state.console.print(details_table("Artifacts", payload["artifacts"].items()))

    @adaptive_app.command("resume", help="Resume one adaptive run after integrity, target, model, and fresh authorization checks.")
    def resume(
        ctx: typer.Context,
        run_id: str = typer.Argument(..., metavar="RUN_ID"),
        authorization: str = typer.Option(..., "--authorization"),
        json_output: bool = typer.Option(False, "--json"),
    ):
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        with operation(state, "Validating and resuming adaptive run…"):
            payload = AdaptiveAssessmentService(state.settings).resume(
                run_id, authorization=authorization
            )
        if state.json_output:
            emit_envelope(state, "adaptive.resume", payload)
        else:
            state.console.print(details_table("Adaptive summary", payload["summary"].model_dump(mode="json").items()))

    @adaptive_app.command("stop", help="Persist a human stop request for an active adaptive run.")
    def stop(
        ctx: typer.Context,
        run_id: str = typer.Argument(..., metavar="RUN_ID"),
        json_output: bool = typer.Option(False, "--json"),
    ):
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        payload = AdaptiveAssessmentService(state.settings).stop(run_id)
        if state.json_output:
            emit_envelope(state, "adaptive.stop", payload)
        else:
            state.console.print(details_table("Adaptive stop", payload.items()))
