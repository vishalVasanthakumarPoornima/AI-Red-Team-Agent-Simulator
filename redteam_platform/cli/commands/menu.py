"""Interactive product menu and safe onboarding."""

from __future__ import annotations

import typer

from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.formatting import data_table, details_table, empty, title, warning
from redteam_platform.cli.prompts import select_number
from redteam_platform.diagnostics import DoctorService, configuration_validation
from redteam_platform.inventory import InventoryService
from redteam_platform.inventory.models import (
    AgentDescriptor,
    ItemType,
    KaliReadiness,
    Listener,
    OllamaModel,
)
from redteam_platform.run_browser import RunBrowser


MENU = """Environment
  1. Discover or refresh local environment
  2. View active AI agents
  3. View Ollama models
  4. View listening services and ports

Assessments
  5. Start an authorized assessment
  6. View current and previous runs
  7. View and export reports

System
  8. Kali readiness
  9. Scope and authorization
 10. Configuration
 11. Diagnostics
 12. Help

  0. Exit"""


def _cached_summary(state: CLIContext) -> tuple[dict, object | None]:
    snapshot = InventoryService(state.settings).cached()
    recent_runs = RunBrowser(state.settings.report_root).list(limit=10)
    warnings = configuration_validation(state.settings)
    data = {
        "Inventory freshness": "not run"
        if snapshot is None
        else ("stale" if snapshot.stale else snapshot.generated_at.isoformat()),
        "Active agents": 0 if snapshot is None else snapshot.summary.active_compatible_agents,
        "Installed Ollama models": 0 if snapshot is None else snapshot.summary.installed_ollama_models,
        "Running Ollama models": 0 if snapshot is None else snapshot.summary.running_ollama_models,
        "Listeners": 0
        if snapshot is None
        else sum(isinstance(item, Listener) for item in snapshot.items),
        "Wildcard listeners": 0 if snapshot is None else snapshot.summary.wildcard_bound_services,
        "Kali": "not requested" if snapshot is None else snapshot.summary.kali_status,
        "Recent runs": len(recent_runs),
        "Configuration warnings": sum(item.status in {"WARN", "FAIL"} for item in warnings),
    }
    return data, snapshot


def _items_table(state: CLIContext, title_text: str, items: list) -> None:
    if not items:
        empty(state, f"No {title_text.lower()} are present in the cached inventory.")
        return
    state.console.print(
        data_table(
            title_text,
            ["Status", "Name", "Type", "Endpoint / path", "Health", "Confidence", "Stable ID"],
            [
                (
                    item.status,
                    item.name,
                    item.item_type,
                    item.endpoint or item.local_path,
                    item.health,
                    item.discovery_confidence,
                    item.stable_id,
                )
                for item in items
            ],
        )
    )


def interactive_menu(state: CLIContext) -> None:
    from redteam_platform.cli.commands.assess import run_wizard

    while True:
        summary, snapshot = _cached_summary(state)
        title(state, "AI Agent Red Team Simulator", "Authorized local and lab assessment only")
        state.console.print(details_table("Environment status", summary.items()))
        if snapshot is None:
            warning(
                state,
                "First run: validate configuration, discover the local environment, then review available agents. No assessment starts automatically.",
            )
        state.console.print(MENU)
        try:
            choice = select_number(
                state,
                "Select",
                {str(number) for number in range(13)},
            )
        except (KeyboardInterrupt, EOFError, typer.Abort):
            state.console.print("\nExited safely.")
            return
        if choice == "0":
            state.console.print("Exited safely.")
            return
        try:
            if choice == "1":
                state.console.print("Refreshing passive local inventory; configured local metadata endpoints may be contacted.")
                refreshed = InventoryService(state.settings).refresh(include_docker=False)
                state.console.print(details_table("Refresh complete", refreshed.summary.model_dump(mode="json").items()))
            elif choice == "2":
                current = snapshot or InventoryService(state.settings).cached()
                _items_table(
                    state,
                    "Active AI agents",
                    [] if current is None else [item for item in current.items if isinstance(item, AgentDescriptor)],
                )
            elif choice == "3":
                current = snapshot or InventoryService(state.settings).cached()
                _items_table(
                    state,
                    "Ollama models",
                    [] if current is None else [item for item in current.items if isinstance(item, OllamaModel)],
                )
            elif choice == "4":
                current = snapshot or InventoryService(state.settings).cached()
                _items_table(
                    state,
                    "Listening services and ports",
                    [] if current is None else [item for item in current.items if item.item_type in {ItemType.LISTENER, ItemType.SERVICE}],
                )
            elif choice == "5":
                run_wizard(state)
            elif choice == "6":
                rows = RunBrowser(state.settings.report_root).list(limit=20)
                if not rows:
                    empty(state, "No assessment runs are available.")
                else:
                    state.console.print(data_table("Runs", ["Run ID", "Status", "Target", "Findings", "Errors"], [(row["run_id"], row["status"], row["target"], row["finding_count"], row["error_count"]) for row in rows]))
            elif choice == "7":
                rows = RunBrowser(state.settings.report_root).reports()
                if not rows:
                    empty(state, "No report artifacts are available.")
                else:
                    state.console.print(data_table("Reports", ["Run ID", "Target", "Formats"], [(row["run_id"], row["target"], row["formats"]) for row in rows]))
            elif choice == "8":
                current = snapshot or InventoryService(state.settings).cached()
                rows = [] if current is None else [item for item in current.items if isinstance(item, KaliReadiness)]
                _items_table(state, "Kali readiness", rows)
                state.console.print("Use `redteam kali check --live` for an explicit bounded SSH readiness check.")
            elif choice == "9":
                state.console.print(details_table("Scope policy", {
                    "Allowed CIDRs": state.settings.allowed_cidrs,
                    "Allowed domains": state.settings.allowed_domains,
                    "Public targets": state.settings.allow_public,
                    "Human authorization required": True,
                }.items()))
            elif choice == "10":
                state.console.print(data_table("Configuration checks", ["Status", "Check", "Explanation"], [(item.status, item.name, item.explanation) for item in configuration_validation(state.settings)]))
            elif choice == "11":
                state.console.print(data_table("Diagnostics", ["Status", "Check", "Explanation"], [(item.status, item.name, item.explanation) for item in DoctorService(state.settings).run(live=False)]))
            elif choice == "12":
                state.console.print("Start safely: config validate → inventory refresh → agents list → assess start.\nUse `redteam help getting-started` for details.")
        except (KeyboardInterrupt, EOFError, typer.Abort):
            state.console.print("\nAction cancelled; returning to the main menu.")


def register(root: typer.Typer) -> None:
    @root.command("menu", help="Open the interactive menu. No integrations refresh automatically.")
    def menu(ctx: typer.Context) -> None:
        state: CLIContext = ctx.find_root().obj
        if state.non_interactive:
            raise typer.BadParameter("The menu is unavailable with --non-interactive.")
        interactive_menu(state)
