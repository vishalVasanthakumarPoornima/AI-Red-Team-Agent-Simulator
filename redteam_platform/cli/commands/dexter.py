"""First-class Dexter discovery, readiness, planning, and assessment commands."""

from __future__ import annotations

from typing import Optional

import typer

from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.errors import CLIError, NonInteractivePromptError
from redteam_platform.cli.exit_codes import ExitCode
from redteam_platform.cli.formatting import (
    data_table,
    details_table,
    emit_envelope,
    empty,
    title,
)
from redteam_platform.cli.progress import operation
from redteam_platform.cli.prompts import confirm, select_number, text
from redteam_platform.dexter.assessment import DexterAssessmentService
from redteam_platform.dexter.discovery import DexterDiscoveryService
from redteam_platform.dexter.models import DexterProfile
from redteam_platform.dexter.plan import DexterPlanService
from redteam_platform.dexter.readiness import DexterReadinessService
from redteam_platform.settings import DexterSettings


def _state(ctx: typer.Context) -> CLIContext:
    return ctx.find_root().obj


def _discovery(state: CLIContext, *, refresh: bool = False):
    with operation(state, "Correlating Dexter configuration and local inventory…"):
        return DexterDiscoveryService(state.settings).discover(refresh=refresh)


def _target(state: CLIContext, dexter_id: str, *, refresh: bool = False):
    with operation(state, "Resolving the exact Dexter deployment…"):
        return DexterDiscoveryService(state.settings).get(
            dexter_id,
            refresh=refresh,
        ).target


def _readiness(state: CLIContext, target):
    with operation(state, "Checking bounded Dexter readiness…"):
        return DexterReadinessService(state.settings).check(target, live=True)


def _render_deployments(state: CLIContext, result) -> None:
    if not result.deployments:
        empty(
            state,
            "No Dexter deployment was found. Configure [redteam.dexter] "
            "api_endpoint or DEXTER_API_ENDPOINT, then run `redteam dexter discover`.",
        )
        return
    state.console.print(
        data_table(
            "Dexter deployments",
            [
                "Status",
                "Name",
                "Type",
                "Endpoint",
                "Scope",
                "Confidence",
                "Components",
                "Stable ID",
            ],
            [
                (
                    deployment.target.health,
                    deployment.target.deployment_name,
                    deployment.target.deployment_type,
                    deployment.target.main_endpoint,
                    deployment.target.scope_classification,
                    deployment.target.discovery_confidence,
                    len(deployment.target.components),
                    deployment.target.stable_id,
                )
                for deployment in result.deployments
            ],
        )
    )
    for error in result.errors:
        state.error_console.print(f"[yellow]{error}[/yellow]")


def _render_target(state: CLIContext, target) -> None:
    state.console.print(
        details_table(
            "Dexter deployment",
            [
                ("Name", target.deployment_name),
                ("Stable ID", target.stable_id),
                ("Type", target.deployment_type),
                ("Main endpoint", target.main_endpoint),
                ("Health endpoint", target.health_endpoint),
                ("Chat endpoint", target.chat_endpoint),
                ("Scope", target.scope_classification),
                ("Confidence", target.discovery_confidence),
                ("Authentication", target.authentication_mode),
                ("Expected model", target.model_name),
                (
                    "Capabilities",
                    {
                        capability.name: capability.available
                        for capability in target.capabilities
                    },
                ),
                ("Evidence", target.discovery_evidence),
            ],
        )
    )
    state.console.print(
        data_table(
            "Dexter components",
            ["Name", "Type", "Status", "Endpoint", "Required", "Inventory IDs"],
            [
                (
                    component.name,
                    component.component_type,
                    component.status,
                    component.endpoint,
                    component.required,
                    component.related_inventory_ids,
                )
                for component in target.components
            ],
        )
    )


def _render_readiness(state: CLIContext, health) -> None:
    state.console.print(
        details_table(
            "Dexter readiness",
            [
                ("Overall", health.overall),
                ("Available coverage", health.available_coverage),
                ("Unavailable coverage", health.unavailable_coverage),
                ("Checked", health.checked_at),
            ],
        )
    )
    state.console.print(
        data_table(
            "Component readiness",
            ["Name", "Type", "Status", "Endpoint", "Evidence", "Errors"],
            [
                (
                    component.name,
                    component.component_type,
                    component.status,
                    component.endpoint,
                    component.evidence,
                    component.errors,
                )
                for component in health.components
            ],
        )
    )


def _render_plan(state: CLIContext, target, readiness, plan) -> None:
    title(
        state,
        "Dexter assessment plan",
        "Every operation below is deterministic, bounded, and visible before execution.",
    )
    _render_target(state, target)
    _render_readiness(state, readiness)
    state.console.print(
        details_table(
            "Plan limits",
            [
                ("Plan ID", plan.plan_id),
                ("Profile", plan.profile),
                ("Scope targets", plan.scope_targets),
                ("Maximum probes", plan.budget.max_probes),
                ("Maximum duration", plan.budget.max_duration_seconds),
                ("Hidden steps", plan.hidden_steps_allowed),
            ],
        )
    )
    state.console.print(
        data_table(
            "Exact ordered steps",
            [
                "ID",
                "Phase",
                "Mode",
                "Category",
                "Requests",
                "Tool",
                "Scope",
                "Operations",
            ],
            [
                (
                    step.step_id,
                    step.phase,
                    step.mode,
                    step.category,
                    step.maximum_requests,
                    step.required_tool,
                    step.scope_target,
                    step.expected_operations,
                )
                for step in plan.steps
            ],
        )
    )


def build_plan(
    state: CLIContext,
    dexter_id: str,
    *,
    profile: DexterProfile,
    include_kali: bool,
    refresh: bool,
):
    target = _target(state, dexter_id, refresh=refresh)
    readiness = _readiness(state, target)
    plan = DexterPlanService().build(
        target,
        readiness,
        profile=profile,
        include_kali=include_kali,
    )
    return target, readiness, plan


def execute_assessment_command(
    state: CLIContext,
    *,
    dexter_id: str,
    profile: DexterProfile,
    authorization: str,
    include_kali: bool,
    refresh: bool,
    yes: bool,
    command: str = "dexter.assess",
) -> dict | None:
    if not authorization or len(authorization.strip()) < 12:
        raise CLIError(
            "A human authorization statement of at least 12 characters is required.",
            ExitCode.SCOPE_OR_AUTHORIZATION_DENIED,
            "missing_authorization",
            "Provide --authorization with your own explicit authority statement.",
        )
    target, readiness, plan = build_plan(
        state,
        dexter_id,
        profile=profile,
        include_kali=include_kali,
        refresh=refresh,
    )
    if not state.json_output:
        _render_plan(state, target, readiness, plan)

    confirmed = profile == DexterProfile.PASSIVE
    interactive_confirmation = False
    if profile != DexterProfile.PASSIVE:
        if state.interactive:
            # Deep-lab never accepts --yes: it requires a prompt answered by a
            # human after the exact scope and operations have been displayed.
            allow_yes = profile != DexterProfile.DEEP_LAB
            confirmed = confirm(
                state,
                "I own or am authorized to test this exact Dexter deployment. Start the displayed plan?",
                default=False,
                allow_yes=allow_yes,
            )
            interactive_confirmation = confirmed
            if not confirmed:
                state.console.print(
                    "Assessment cancelled before execution; no run was created."
                )
                return None
        else:
            if profile == DexterProfile.DEEP_LAB:
                raise NonInteractivePromptError(
                    "Deep-lab requires a real interactive confirmation after plan review."
                )
            # A complete explicit assess command (exact stable ID, profile, and
            # human statement) is the non-interactive confirmation boundary.
            # --yes remains an eligible UI convenience and never authorization.
            confirmed = True

    progress_rows: list[dict] = []

    def progress(payload: dict) -> None:
        progress_rows.append(payload)
        if state.verbose and not state.json_output:
            state.console.print(
                f"[dim]{payload['phase']}[/dim] {payload['step']} — "
                f"{payload['completed_steps']}/{payload['total_steps']} steps, "
                f"{payload['elapsed_seconds']:.1f}s, "
                f"{payload['finding_count']} findings, {payload['error_count']} errors"
            )

    with operation(state, "Running the confirmed bounded Dexter plan…"):
        summary, findings, reports = DexterAssessmentService(
            state.settings
        ).assess(
            target,
            plan,
            authorization_statement=authorization,
            confirmed=confirmed,
            interactive_confirmation=interactive_confirmation,
            include_kali=include_kali,
            progress_callback=progress,
        )
    result = {
        "summary": summary,
        "findings": findings,
        "reports": reports,
        "progress_event_count": len(progress_rows),
    }
    if state.json_output:
        emit_envelope(state, command, result)
    else:
        state.console.print(
            details_table(
                "Dexter assessment result",
                summary.model_dump(mode="json").items(),
            )
        )
        state.console.print(
            data_table(
                "Dexter findings",
                ["ID", "Severity", "Status", "Category", "Title"],
                [
                    (
                        finding.finding_id,
                        finding.severity,
                        finding.status,
                        finding.category,
                        finding.title,
                    )
                    for finding in findings
                ],
            )
        )
        state.console.print(
            details_table(
                "Coverage",
                [
                    ("Completed", summary.coverage_complete),
                    ("Percentage", f"{summary.coverage_percentage:.1f}%"),
                    ("Unavailable steps", summary.unavailable_steps),
                    ("Failed steps", summary.failed_steps),
                    ("Skipped steps", summary.skipped_steps),
                ],
            )
        )
        state.console.print(details_table("Artifacts", reports.items()))
    return result


def run_wizard(state: CLIContext) -> None:
    if state.non_interactive:
        raise NonInteractivePromptError(
            "The Dexter assessment wizard is unavailable in non-interactive mode."
        )
    result = _discovery(state)
    _render_deployments(state, result)
    if not result.deployments:
        return
    choices = {
        str(index): deployment
        for index, deployment in enumerate(result.deployments, 1)
    }
    selected = select_number(
        state,
        "Dexter deployment (0 cancels)",
        {"0", *choices},
    )
    if selected == "0":
        state.console.print("Assessment cancelled before side effects.")
        return
    profile = DexterProfile(
        text(
            state,
            "Profile (passive/standard/deep-lab)",
            default="standard",
        ).strip()
    )
    authorization = text(
        state,
        f"Human authorization statement for {choices[selected].target.main_endpoint}",
    )
    include_kali = (
        profile != DexterProfile.PASSIVE
        and confirm(
            state,
            "Include optional deterministic Kali checks if ready?",
            default=False,
            allow_yes=False,
        )
    )
    execute_assessment_command(
        state,
        dexter_id=choices[selected].target.stable_id,
        profile=profile,
        authorization=authorization,
        include_kali=include_kali,
        refresh=False,
        yes=False,
    )


def register(root: typer.Typer, dexter_app: typer.Typer) -> None:
    root.add_typer(dexter_app, name="dexter")

    @dexter_app.callback(invoke_without_command=True)
    def dexter_root(
        ctx: typer.Context,
        name: Optional[str] = typer.Option(None, "--dexter-name"),
        endpoint: Optional[str] = typer.Option(None, "--endpoint"),
        health_route: Optional[str] = typer.Option(None, "--health-route"),
        chat_route: Optional[str] = typer.Option(None, "--chat-route"),
        metadata_route: Optional[str] = typer.Option(None, "--metadata-route"),
        openapi_route: Optional[str] = typer.Option(None, "--openapi-route"),
        authentication_mode: Optional[str] = typer.Option(None, "--auth-mode"),
        authentication_reference: Optional[str] = typer.Option(
            None, "--auth-reference"
        ),
        ollama_endpoint: Optional[str] = typer.Option(None, "--ollama-endpoint"),
        expected_model: Optional[str] = typer.Option(None, "--expected-model"),
        tool_endpoints: Optional[list[str]] = typer.Option(
            None, "--tool-endpoint"
        ),
        memory_endpoint: Optional[str] = typer.Option(None, "--memory-endpoint"),
        vector_endpoint: Optional[str] = typer.Option(None, "--vector-endpoint"),
        retrieval_endpoint: Optional[str] = typer.Option(
            None, "--retrieval-endpoint"
        ),
        voice_endpoints: Optional[list[str]] = typer.Option(
            None, "--voice-endpoint"
        ),
        expected_ports: Optional[list[int]] = typer.Option(
            None, "--expected-port", min=1, max=65535
        ),
        requires_kali_tunnel: Optional[bool] = typer.Option(
            None, "--requires-kali-tunnel/--no-kali-tunnel"
        ),
    ) -> None:
        state = _state(ctx)
        overrides = {
            "name": name,
            "api_endpoint": endpoint,
            "health_path": health_route,
            "chat_path": chat_route,
            "metadata_path": metadata_route,
            "openapi_path": openapi_route,
            "authentication_mode": authentication_mode,
            "authentication_reference": authentication_reference,
            "ollama_endpoint": ollama_endpoint,
            "expected_model": expected_model,
            "tool_endpoints": tool_endpoints,
            "memory_endpoint": memory_endpoint,
            "vector_endpoint": vector_endpoint,
            "retrieval_endpoint": retrieval_endpoint,
            "voice_endpoints": voice_endpoints,
            "expected_ports": expected_ports,
            "requires_kali_tunnel": requires_kali_tunnel,
        }
        supplied = {key: value for key, value in overrides.items() if value is not None}
        if supplied:
            dexter_settings = DexterSettings.model_validate(
                {
                    **state.settings.dexter.model_dump(mode="python"),
                    **supplied,
                }
            )
            state.settings = state.settings.model_copy(
                update={"dexter": dexter_settings}
            )
        if ctx.invoked_subcommand is not None:
            return
        if state.interactive:
            run_wizard(state)
        else:
            state.console.print(ctx.get_help())

    @dexter_app.command("discover", help="Safely correlate configured and locally discovered Dexter deployments.")
    def discover(
        ctx: typer.Context,
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        result = _discovery(state, refresh=refresh)
        if state.json_output:
            emit_envelope(state, "dexter.discover", result, errors=result.errors)
        else:
            _render_deployments(state, result)

    @dexter_app.command("list", help="List correlated Dexter deployments.")
    def list_deployments(
        ctx: typer.Context,
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        result = _discovery(state, refresh=refresh)
        if state.json_output:
            emit_envelope(state, "dexter.list", result, errors=result.errors)
        else:
            _render_deployments(state, result)

    @dexter_app.command("show", help="Show one Dexter deployment, its evidence, and components.")
    def show(
        ctx: typer.Context,
        dexter_id: str = typer.Argument(..., metavar="DEXTER_ID"),
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        target = _target(state, dexter_id, refresh=refresh)
        if state.json_output:
            emit_envelope(state, "dexter.show", target)
        else:
            _render_target(state, target)

    @dexter_app.command("health", help="Run bounded passive Dexter component readiness checks.")
    def health(
        ctx: typer.Context,
        dexter_id: str = typer.Argument(..., metavar="DEXTER_ID"),
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        target = _target(state, dexter_id, refresh=refresh)
        result = _readiness(state, target)
        if state.json_output:
            emit_envelope(state, "dexter.health", result)
        else:
            _render_readiness(state, result)

    @dexter_app.command("plan", help="Display the complete deterministic Dexter plan without creating a run.")
    def plan(
        ctx: typer.Context,
        dexter_id: str = typer.Argument(..., metavar="DEXTER_ID"),
        profile: DexterProfile = typer.Option(DexterProfile.STANDARD, "--profile"),
        include_kali: bool = typer.Option(False, "--include-kali"),
        refresh: bool = typer.Option(False, "--refresh"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        target, readiness, result = build_plan(
            state,
            dexter_id,
            profile=profile,
            include_kali=include_kali,
            refresh=refresh,
        )
        if state.json_output:
            emit_envelope(
                state,
                "dexter.plan",
                {"target": target, "readiness": readiness, "plan": result},
            )
        else:
            _render_plan(state, target, readiness, result)

    @dexter_app.command("assess", help="Run a confirmed bounded Dexter assessment and write complete artifacts.")
    def assess(
        ctx: typer.Context,
        dexter_id: str = typer.Argument(..., metavar="DEXTER_ID"),
        profile: DexterProfile = typer.Option(DexterProfile.STANDARD, "--profile"),
        authorization: str = typer.Option(..., "--authorization"),
        include_kali: bool = typer.Option(False, "--include-kali"),
        refresh: bool = typer.Option(False, "--refresh"),
        yes: bool = typer.Option(False, "--yes"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        execute_assessment_command(
            state,
            dexter_id=dexter_id,
            profile=profile,
            authorization=authorization,
            include_kali=include_kali,
            refresh=refresh,
            yes=yes,
        )
