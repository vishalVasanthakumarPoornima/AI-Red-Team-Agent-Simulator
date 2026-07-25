"""Safe assessment planning, non-interactive launch, and guided wizard."""

from __future__ import annotations

from typing import Optional

import typer

from redteam_platform.adaptive import PROBE_TEMPLATES
from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.errors import CLIError, NonInteractivePromptError
from redteam_platform.cli.exit_codes import ExitCode
from redteam_platform.cli.formatting import data_table, details_table, emit_envelope, title, warning
from redteam_platform.cli.progress import operation
from redteam_platform.cli.prompts import confirm, select_number, text
from redteam_platform.inventory import InventoryService
from redteam_platform.inventory.models import (
    AgentDescriptor,
    ItemType,
    OllamaEndpoint,
    ServiceEndpoint,
)
from redteam_platform.schemas import AssessmentBudget, AssessmentProfile
from redteam_platform.service import ApplicationService
from redteam_platform.assessments import UnifiedAssessmentService
from redteam_platform.targets.models import TargetKind


SUPPORTED_KINDS = {"python", "http", "openai", "ollama", "dexter"}
PLANNED_KINDS = {"host", "web"}
DEFAULT_CATEGORIES = [
    name
    for name in PROBE_TEMPLATES
    if name not in {"web_headers", "web_metadata", "tls_observation", "host_port"}
]


def _state(ctx: typer.Context) -> CLIContext:
    return ctx.find_root().obj


def _budget(rounds: int, probes: int, model_calls: int, duration: int) -> AssessmentBudget:
    return AssessmentBudget(
        max_rounds=rounds,
        max_probes=probes,
        max_model_calls=model_calls,
        max_duration_seconds=duration,
    )


def _prepare(
    state: CLIContext,
    *,
    kind: str,
    target: str,
    authorization: str,
    profile: AssessmentProfile,
    categories: list[str] | None,
    planner_model: str | None,
    target_model: str | None,
    budget: AssessmentBudget,
    public: bool,
    confirmed: bool,
):
    normalized_kind = kind.lower()
    if normalized_kind in PLANNED_KINDS:
        raise CLIError(
            f"{normalized_kind} assessment is planned but not available in the Phase 3 workflow.",
            ExitCode.TARGET_UNAVAILABLE,
            "planned_feature_unavailable",
            "Choose python, http, openai, or ollama.",
        )
    if normalized_kind not in SUPPORTED_KINDS:
        raise CLIError(
            f"Unsupported assessment kind: {kind}",
            ExitCode.INVALID_USAGE,
            "unsupported_assessment_kind",
        )
    if not authorization or len(authorization.strip()) < 12:
        raise CLIError(
            "A human authorization statement of at least 12 characters is required.",
            ExitCode.SCOPE_OR_AUTHORIZATION_DENIED,
            "missing_authorization",
            "Provide --authorization with your own explicit authority statement.",
        )
    return ApplicationService(state.settings).plan(
        kind=normalized_kind,
        value=target,
        statement=authorization,
        source="human-cli",
        profile=profile,
        categories=categories,
        planner_model=planner_model,
        target_model=target_model,
        budget=budget,
        public_mode=public,
        # A flag can acknowledge a local command flow, but it is never proof of
        # an interactive public-target confirmation.
        interactive_confirmation=confirmed and state.interactive,
    )


def _summary(request) -> dict:
    return {
        "target": request.target.name,
        "normalized_target": request.authorization.decision.normalized_target,
        "target_type": request.target.target_type,
        "scope": request.authorization.decision.classification,
        "profile": request.profile,
        "active": request.profile != AssessmentProfile.PASSIVE,
        "expected_operations": request.categories or DEFAULT_CATEGORIES,
        "budget": request.budget.model_dump(mode="json"),
        "authorization_required": True,
        "authorization_recorded": True,
    }


def _render_confirmation(state: CLIContext, request) -> None:
    title(state, "Authorized assessment review", "Active operations begin only after final confirmation")
    state.console.print(details_table("Exact assessment", _summary(request).items()))


def _execute(state: CLIContext, request) -> dict:
    events: list[dict] = []

    def event_callback(event) -> None:
        if state.verbose and not state.json_output:
            state.console.print(f"[dim]{event.phase}[/dim] {event.action}: {event.status}")
        events.append(event.model_dump(mode="json"))

    with operation(state, "Running bounded authorized assessment…"):
        summary, findings, reports = ApplicationService(state.settings).run(
            request,
            event_callback=event_callback,
        )
    return {
        "summary": summary,
        "findings": findings,
        "reports": reports,
        "event_count": len(events),
    }


KIND_HINTS = {
    "python": TargetKind.PYTHON_AGENT,
    "agent": TargetKind.HTTP_AGENT,
    "http": TargetKind.HTTP_AGENT,
    "openai": TargetKind.OPENAI_COMPATIBLE,
    "ollama": TargetKind.OLLAMA_ENDPOINT,
    "host": TargetKind.HOST,
    "web": TargetKind.WEB_APPLICATION,
}


def _unified_plan(
    state: CLIContext,
    *,
    command: str,
    target: str,
    kind: str | None,
    profile: AssessmentProfile,
    model: str | None,
    ports: list[int] | None,
    paths: list[str] | None,
    include_kali: bool,
    json_output: bool,
) -> None:
    service = UnifiedAssessmentService(state.settings)
    resolution = service.resolve(
        target,
        kind_hint=KIND_HINTS.get(kind or ""),
        model_name=model,
        ports=ports,
    )
    if resolution.target and resolution.target.target_kind == TargetKind.DEXTER:
        from redteam_platform.cli.commands.dexter import build_plan, _render_plan
        from redteam_platform.dexter.models import DexterProfile

        dexter_target, dexter_readiness, dexter_plan = build_plan(
            state,
            resolution.target.stable_id,
            profile=DexterProfile(profile.value),
            include_kali=include_kali,
            refresh=False,
        )
        payload = {
            "target": dexter_target,
            "readiness": dexter_readiness,
            "plan": dexter_plan,
        }
        if state.json_output or json_output:
            emit_envelope(state, command, payload)
        else:
            _render_plan(state, dexter_target, dexter_readiness, dexter_plan)
        return
    descriptor, health, plan = service.plan(
        target,
        profile=profile,
        kind_hint=KIND_HINTS.get(kind or ""),
        model_name=model,
        ports=ports,
        paths=paths,
        include_kali=include_kali,
    )
    payload = {"target": descriptor, "health": health, "plan": plan}
    if state.json_output or json_output:
        emit_envelope(state, command, payload)
    else:
        state.console.print(details_table("Target", descriptor.model_dump(mode="json").items()))
        state.console.print(details_table("Health", health.model_dump(mode="json").items()))
        state.console.print(details_table("Deterministic plan", plan.model_dump(mode="json").items()))


def _unified_run(
    state: CLIContext,
    *,
    command: str,
    target: str,
    authorization: str | None,
    kind: str | None,
    profile: AssessmentProfile,
    model: str | None,
    ports: list[int] | None,
    paths: list[str] | None,
    include_kali: bool,
    public: bool,
    yes: bool,
    json_output: bool,
) -> None:
    if not authorization:
        raise CLIError(
            "Missing required --authorization.",
            ExitCode.SCOPE_OR_AUTHORIZATION_DENIED,
            "missing_authorization",
        )
    service = UnifiedAssessmentService(state.settings)
    resolution = service.resolve(
        target,
        kind_hint=KIND_HINTS.get(kind or ""),
        model_name=model,
        ports=ports,
    )
    if resolution.target and resolution.target.target_kind == TargetKind.DEXTER:
        from redteam_platform.cli.commands.dexter import execute_assessment_command
        from redteam_platform.dexter.models import DexterProfile

        execute_assessment_command(
            state,
            dexter_id=resolution.target.stable_id,
            profile=DexterProfile(profile.value),
            authorization=authorization,
            include_kali=include_kali,
            refresh=False,
            yes=yes,
            command=command,
        )
        return
    with operation(state, "Running deterministic authorized assessment…"):
        result = service.run(
            target,
            authorization=authorization,
            profile=profile,
            kind_hint=KIND_HINTS.get(kind or ""),
            model_name=model,
            ports=ports,
            paths=paths,
            include_kali=include_kali,
            public_mode=public,
            interactive_confirmation=(yes or state.interactive),
        )
    if state.json_output or json_output:
        emit_envelope(state, command, result)
    else:
        state.console.print(
            details_table(
                "Assessment result",
                result["summary"].model_dump(mode="json").items(),
            )
        )
        state.console.print(details_table("Artifacts", result["artifacts"].items()))


def run_wizard(state: CLIContext) -> None:
    if state.non_interactive:
        raise NonInteractivePromptError(
            "The assessment wizard is unavailable in non-interactive mode."
        )
    title(state, "Start an authorized assessment", "Only currently supported local agent services are launchable")
    state.console.print(
        "Target types\n"
        "  1. Enrolled Python target\n"
        "  2. Compatible local HTTP agent\n"
        "  3. Ollama endpoint\n"
        "  4. OpenAI-compatible local endpoint\n"
        "  5. Manual supported target\n"
        "  6. First-class Dexter deployment\n"
        "  0. Cancel"
    )
    choice = select_number(state, "Target type", set("0123456"))
    if choice == "0":
        state.console.print("Assessment cancelled before side effects.")
        return
    if choice == "6":
        from redteam_platform.cli.commands.dexter import run_wizard as run_dexter_wizard

        run_dexter_wizard(state)
        return
    kind = {"1": "python", "2": "http", "3": "ollama", "4": "openai"}.get(choice)
    snapshot = InventoryService(state.settings).collect(
        include_docker=False,
        include_kali=False,
        refresh=False,
    )
    candidates: list[tuple[str, str, object]] = []
    for item in snapshot.items:
        if choice == "1" and isinstance(item, AgentDescriptor) and item.item_type == ItemType.PYTHON_TARGET:
            candidates.append(("python", item.name, item))
        elif choice == "2" and (
            isinstance(item, AgentDescriptor) and item.endpoint
            or isinstance(item, ServiceEndpoint) and item.service_kind != "unknown_http"
        ):
            candidates.append(("http", item.endpoint or item.name, item))
        elif choice == "3" and isinstance(item, OllamaEndpoint):
            candidates.append(("ollama", item.base_url, item))
    if choice == "5" or not candidates:
        kind = kind or text(state, "Kind (python/http/openai/ollama)", default="python").strip().lower()
        target = text(state, "Exact target")
    else:
        state.console.print(
            data_table(
                "Discovered candidates",
                ["#", "Name", "Type", "Endpoint / path", "Health", "Scope", "Confidence", "Model / process", "Stable ID"],
                [
                    (
                        index,
                        item.name,
                        item.item_type,
                        item.endpoint or item.local_path,
                        item.health,
                        item.scope_classification,
                        item.discovery_confidence,
                        getattr(item, "model_name", None) or item.process_name,
                        item.stable_id,
                    )
                    for index, (_, _, item) in enumerate(candidates, 1)
                ],
            )
        )
        selected = select_number(
            state,
            "Target",
            {"0", *(str(index) for index in range(1, len(candidates) + 1))},
        )
        if selected == "0":
            state.console.print("Assessment cancelled before side effects.")
            return
        kind, target, _ = candidates[int(selected) - 1]
    if kind not in SUPPORTED_KINDS:
        warning(state, f"{kind} is not available in the Phase 3 workflow.")
        return
    scope_target = target
    if kind == "python" and not str(target).startswith("python://"):
        scope_target = f"python://{target}"
    decision = ApplicationService(state.settings).policy.decide(scope_target, active=False)
    state.console.print(
        details_table(
            "Normalized target",
            [
                ("Original", target),
                ("Normalized", decision.normalized_target),
                ("Classification", decision.classification),
                ("Allowed", decision.allowed),
                ("Rule", decision.policy_rule),
                ("Reason", decision.reason),
            ],
        )
    )
    if not decision.allowed:
        warning(state, "Target denied. No executor was called and no run was created.")
        return
    category_text = text(
        state,
        "Assessment category",
        default="prompt_disclosure",
    ).strip()
    if category_text not in PROBE_TEMPLATES:
        warning(state, f"Unknown registered category: {category_text}")
        return
    profile = AssessmentProfile(text(state, "Profile (passive/standard/deep-lab)", default="standard"))
    target_model = None
    if kind in {"ollama", "openai"}:
        target_model = text(state, "Exact target model")
    authorization = text(
        state,
        f"Human authorization statement for {decision.normalized_target}",
    )
    request = _prepare(
        state,
        kind=kind,
        target=target,
        authorization=authorization,
        profile=profile,
        categories=[category_text],
        planner_model=None,
        target_model=target_model,
        budget=AssessmentBudget(),
        public=False,
        confirmed=True,
    )
    _render_confirmation(state, request)
    if not confirm(
        state,
        "I own or am authorized to test this exact target. Start now?",
        default=False,
        allow_yes=True,
    ):
        state.console.print("Assessment cancelled before execution; no run was created.")
        return
    result = _execute(state, request)
    state.console.print(details_table("Assessment result", result["summary"].model_dump(mode="json").items()))
    state.console.print(details_table("Artifact locations", result["reports"].items()))


def register(root: typer.Typer, assess_app: typer.Typer) -> None:
    root.add_typer(assess_app, name="assess")

    @assess_app.callback(invoke_without_command=True)
    def assess_root(ctx: typer.Context) -> None:
        if ctx.invoked_subcommand is not None:
            return
        state = _state(ctx)
        if state.interactive:
            run_wizard(state)
        else:
            state.console.print(ctx.get_help())

    def start_impl(
        ctx: typer.Context,
        target: Optional[str],
        authorization: Optional[str],
        kind: str,
        profile: AssessmentProfile,
        category: Optional[list[str]],
        planner_model: Optional[str],
        target_model: Optional[str],
        rounds: int,
        probes: int,
        model_calls: int,
        duration: int,
        public: bool,
        yes: bool,
        plan_only: bool,
        json_output: bool,
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        if not target:
            if state.interactive and not plan_only:
                run_wizard(state)
                return
            raise CLIError("Missing required --target.", ExitCode.INVALID_USAGE, "missing_target")
        if not authorization:
            raise CLIError(
                "Missing required --authorization.",
                ExitCode.SCOPE_OR_AUTHORIZATION_DENIED,
                "missing_authorization",
            )
        if kind.lower() == "dexter":
            from redteam_platform.cli.commands.dexter import (
                build_plan,
                execute_assessment_command,
                _render_plan,
            )
            from redteam_platform.dexter.models import DexterProfile

            dexter_profile = DexterProfile(profile.value)
            if plan_only:
                dexter_target, dexter_readiness, dexter_plan = build_plan(
                    state,
                    target,
                    profile=dexter_profile,
                    include_kali=False,
                    refresh=False,
                )
                if state.json_output or json_output:
                    emit_envelope(
                        state,
                        "assess.plan",
                        {
                            "target": dexter_target,
                            "readiness": dexter_readiness,
                            "plan": dexter_plan,
                        },
                    )
                else:
                    _render_plan(
                        state,
                        dexter_target,
                        dexter_readiness,
                        dexter_plan,
                    )
                return
            execute_assessment_command(
                state,
                dexter_id=target,
                profile=dexter_profile,
                authorization=authorization,
                include_kali=False,
                refresh=False,
                yes=yes,
                command="assess.start",
            )
            return
        request = _prepare(
            state,
            kind=kind,
            target=target,
            authorization=authorization,
            profile=profile,
            categories=category,
            planner_model=planner_model,
            target_model=target_model,
            budget=_budget(rounds, probes, model_calls, duration),
            public=public,
            confirmed=yes or state.interactive,
        )
        if plan_only:
            if state.json_output or json_output:
                emit_envelope(state, "assess.plan", request)
            else:
                _render_confirmation(state, request)
            return
        _render_confirmation(state, request) if not (state.json_output or json_output) else None
        if state.interactive and not yes and not confirm(
            state,
            "I own or am authorized to test this exact target. Start now?",
            default=False,
            allow_yes=False,
        ):
            state.console.print("Assessment cancelled before execution; no run was created.")
            return
        result = _execute(state, request)
        if state.json_output or json_output:
            emit_envelope(state, "assess.start", result)
        else:
            state.console.print(details_table("Assessment result", result["summary"].model_dump(mode="json").items()))
            state.console.print(details_table("Artifacts", result["reports"].items()))

    @assess_app.command("start", help="Launch a bounded active assessment after scope and human authorization checks.")
    def start(
        ctx: typer.Context,
        target: Optional[str] = typer.Option(None, "--target"),
        authorization: Optional[str] = typer.Option(None, "--authorization"),
        kind: str = typer.Option("python", "--kind"),
        profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD, "--profile"),
        category: Optional[list[str]] = typer.Option(None, "--category"),
        planner_model: Optional[str] = typer.Option(None, "--planner-model"),
        target_model: Optional[str] = typer.Option(None, "--target-model"),
        rounds: int = typer.Option(8, min=1, max=50),
        probes: int = typer.Option(100, min=1, max=1000),
        model_calls: int = typer.Option(24, min=0, max=500),
        duration: int = typer.Option(1200, min=1, max=86400),
        public: bool = typer.Option(False, "--public"),
        yes: bool = typer.Option(False, "--yes"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        start_impl(ctx, target, authorization, kind, profile, category, planner_model, target_model, rounds, probes, model_calls, duration, public, yes, False, json_output)

    @assess_app.command("plan", help="Validate and display an assessment plan without creating a run.")
    def plan(
        ctx: typer.Context,
        target_arg: Optional[str] = typer.Argument(None, metavar="TARGET"),
        target: Optional[str] = typer.Option(None, "--target"),
        authorization: Optional[str] = typer.Option(None, "--authorization"),
        kind: str = typer.Option("python", "--kind"),
        profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD, "--profile"),
        category: Optional[list[str]] = typer.Option(None, "--category"),
        planner_model: Optional[str] = typer.Option(None, "--planner-model"),
        target_model: Optional[str] = typer.Option(None, "--target-model"),
        rounds: int = typer.Option(8, min=1, max=50),
        probes: int = typer.Option(100, min=1, max=1000),
        model_calls: int = typer.Option(24, min=0, max=500),
        duration: int = typer.Option(1200, min=1, max=86400),
        public: bool = typer.Option(False, "--public"),
        yes: bool = typer.Option(False, "--yes"),
        model: Optional[str] = typer.Option(None, "--model"),
        port: Optional[list[int]] = typer.Option(None, "--port"),
        path: Optional[list[str]] = typer.Option(None, "--path"),
        include_kali: bool = typer.Option(False, "--include-kali"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        if target_arg:
            _unified_plan(
                state,
                command="assess.plan",
                target=target_arg,
                kind=None if kind == "python" else kind,
                profile=profile,
                model=model or target_model,
                ports=port,
                paths=path,
                include_kali=include_kali,
                json_output=json_output,
            )
            return
        if not target:
            raise CLIError("Missing target.", ExitCode.INVALID_USAGE, "missing_target")
        if not authorization:
            raise CLIError(
                "Missing required --authorization for legacy option-based planning.",
                ExitCode.SCOPE_OR_AUTHORIZATION_DENIED,
                "missing_authorization",
            )
        start_impl(ctx, target, authorization, kind, profile, category, planner_model, target_model, rounds, probes, model_calls, duration, public, yes, True, json_output)

    @assess_app.command("local-agent", help="Assess an enrolled Python target with the same scope and authorization controls.")
    def local_agent(
        ctx: typer.Context,
        target: str = typer.Option(..., "--target"),
        authorization: str = typer.Option(..., "--authorization"),
        category: Optional[list[str]] = typer.Option(None, "--category"),
        yes: bool = typer.Option(False, "--yes"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        start_impl(ctx, target, authorization, "python", AssessmentProfile.STANDARD, category, None, None, 8, 100, 24, 1200, False, yes, False, json_output)

    @assess_app.command("python-target", help="Alias for `assess local-agent`.")
    def python_target(
        ctx: typer.Context,
        target: str = typer.Option(..., "--target"),
        authorization: str = typer.Option(..., "--authorization"),
        category: Optional[list[str]] = typer.Option(None, "--category"),
        yes: bool = typer.Option(False, "--yes"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        start_impl(ctx, target, authorization, "python", AssessmentProfile.STANDARD, category, None, None, 8, 100, 24, 1200, False, yes, False, json_output)

    @assess_app.command("run", help="Run a unified deterministic assessment; legacy options remain accepted.")
    def legacy_run(
        ctx: typer.Context,
        target_arg: Optional[str] = typer.Argument(None, metavar="TARGET"),
        target: Optional[str] = typer.Option(None, "--target"),
        authorization: Optional[str] = typer.Option(None, "--authorization"),
        kind: str = typer.Option("python", "--kind"),
        profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD, "--profile"),
        category: Optional[list[str]] = typer.Option(None, "--category"),
        planner_model: Optional[str] = typer.Option(None, "--planner-model"),
        target_model: Optional[str] = typer.Option(None, "--target-model"),
        rounds: int = typer.Option(8, min=1, max=50),
        probes: int = typer.Option(100, min=1, max=1000),
        model_calls: int = typer.Option(24, min=0, max=500),
        duration: int = typer.Option(1200, min=1, max=86400),
        public: bool = typer.Option(False, "--public"),
        yes: bool = typer.Option(False, "--yes"),
        model: Optional[str] = typer.Option(None, "--model"),
        port: Optional[list[int]] = typer.Option(None, "--port"),
        path: Optional[list[str]] = typer.Option(None, "--path"),
        include_kali: bool = typer.Option(False, "--include-kali"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        if target_arg:
            _unified_run(
                state,
                command="assess.run",
                target=target_arg,
                authorization=authorization,
                kind=None if kind == "python" else kind,
                profile=profile,
                model=model or target_model,
                ports=port,
                paths=path,
                include_kali=include_kali,
                public=public,
                yes=yes,
                json_output=json_output,
            )
            return
        if not target:
            raise CLIError("Missing target.", ExitCode.INVALID_USAGE, "missing_target")
        start_impl(ctx, target, authorization, kind, profile, category, planner_model, target_model, rounds, probes, model_calls, duration, public, yes, False, json_output)

    def typed_command(
        ctx: typer.Context,
        *,
        command: str,
        kind: str,
        target: str,
        authorization: Optional[str],
        profile: AssessmentProfile,
        model: Optional[str],
        port: Optional[list[int]],
        path: Optional[list[str]],
        include_kali: bool,
        public: bool,
        yes: bool,
        json_output: bool,
    ) -> None:
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        _unified_run(
            state,
            command=command,
            target=target,
            authorization=authorization,
            kind=kind,
            profile=profile,
            model=model,
            ports=port,
            paths=path,
            include_kali=include_kali,
            public=public,
            yes=yes,
            json_output=json_output,
        )

    def typed_options(kind_name: str):
        return kind_name

    @assess_app.command("python", help="Assess an explicitly enrolled Python target.")
    def python_command(
        ctx: typer.Context,
        target: str = typer.Argument(...),
        authorization: Optional[str] = typer.Option(None, "--authorization"),
        profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD, "--profile"),
        yes: bool = typer.Option(False, "--yes"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        typed_command(ctx, command="assess.python", kind="python", target=target, authorization=authorization, profile=profile, model=None, port=None, path=None, include_kali=False, public=False, yes=yes, json_output=json_output)

    @assess_app.command("agent", help="Assess an HTTP or OpenAI-compatible AI agent.")
    def agent_command(
        ctx: typer.Context,
        target: str = typer.Argument(...),
        authorization: Optional[str] = typer.Option(None, "--authorization"),
        kind: str = typer.Option("agent", "--kind"),
        profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD, "--profile"),
        model: Optional[str] = typer.Option(None, "--model"),
        yes: bool = typer.Option(False, "--yes"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        typed_command(ctx, command="assess.agent", kind=kind, target=target, authorization=authorization, profile=profile, model=model, port=None, path=None, include_kali=False, public=False, yes=yes, json_output=json_output)

    @assess_app.command("ollama", help="Assess an explicitly selected Ollama model endpoint.")
    def ollama_command(
        ctx: typer.Context,
        target: str = typer.Argument(...),
        authorization: Optional[str] = typer.Option(None, "--authorization"),
        profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD, "--profile"),
        model: Optional[str] = typer.Option(None, "--model"),
        yes: bool = typer.Option(False, "--yes"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        typed_command(ctx, command="assess.ollama", kind="ollama", target=target, authorization=authorization, profile=profile, model=model, port=None, path=None, include_kali=False, public=False, yes=yes, json_output=json_output)

    @assess_app.command("host", help="Assess one host using only explicit approved ports.")
    def host_command(
        ctx: typer.Context,
        target: str = typer.Argument(...),
        authorization: Optional[str] = typer.Option(None, "--authorization"),
        profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD, "--profile"),
        port: Optional[list[int]] = typer.Option(None, "--port"),
        include_kali: bool = typer.Option(False, "--include-kali"),
        yes: bool = typer.Option(False, "--yes"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        typed_command(ctx, command="assess.host", kind="host", target=target, authorization=authorization, profile=profile, model=None, port=port, path=None, include_kali=include_kali, public=False, yes=yes, json_output=json_output)

    @assess_app.command("web", help="Assess one authorized website or web application.")
    def web_command(
        ctx: typer.Context,
        target: str = typer.Argument(...),
        authorization: Optional[str] = typer.Option(None, "--authorization"),
        profile: AssessmentProfile = typer.Option(AssessmentProfile.STANDARD, "--profile"),
        path: Optional[list[str]] = typer.Option(None, "--path"),
        public: bool = typer.Option(False, "--public"),
        yes: bool = typer.Option(False, "--yes"),
        json_output: bool = typer.Option(False, "--json"),
    ) -> None:
        typed_command(ctx, command="assess.web", kind="web", target=target, authorization=authorization, profile=profile, model=None, port=None, path=path, include_kali=False, public=public, yes=yes, json_output=json_output)
