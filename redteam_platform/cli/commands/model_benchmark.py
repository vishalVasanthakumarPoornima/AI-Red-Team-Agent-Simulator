"""Phase 6 model benchmark and recommendation CLI."""

from __future__ import annotations

from typing import Optional

import typer

from redteam_platform.adaptive_engine.benchmark import ModelBenchmarkService
from redteam_platform.cli.context import CLIContext
from redteam_platform.cli.formatting import data_table, details_table, emit_envelope
from redteam_platform.cli.progress import operation


def _state(ctx: typer.Context) -> CLIContext:
    return ctx.find_root().obj


def register(models_app: typer.Typer) -> None:
    @models_app.command("benchmark", help="Run the synthetic local adaptive benchmark.")
    def benchmark(
        ctx: typer.Context,
        model: Optional[str] = typer.Argument(None, metavar="MODEL"),
        all_installed: bool = typer.Option(False, "--all-installed"),
        json_output: bool = typer.Option(False, "--json"),
    ):
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        if bool(model) == all_installed:
            raise ValueError("Provide exactly one MODEL or --all-installed.")
        service = ModelBenchmarkService(state.settings)
        with operation(state, "Running synthetic adaptive model benchmark…"):
            payload = (
                service.run_all_installed()
                if all_installed
                else service.run([str(model)])
            )
        if state.json_output:
            emit_envelope(state, "models.benchmark", payload)
        else:
            state.console.print(
                details_table(
                    "Benchmark",
                    [
                        ("ID", payload["report"].benchmark_id),
                        ("Dataset", payload["report"].dataset_version),
                        ("Models", payload["report"].models),
                    ],
                )
            )
            state.console.print(
                data_table(
                    "Metrics",
                    ["Model", "Score", "Validity", "Policy", "Correct", "Latency"],
                    [
                        (
                            row.model,
                            row.weighted_score,
                            row.structured_output_validity,
                            row.policy_compliance,
                            row.correct_decision_rate,
                            row.median_latency_seconds,
                        )
                        for row in payload["report"].metrics
                    ],
                )
            )
            state.console.print(details_table("Artifacts", payload["artifacts"].items()))

    @models_app.command("recommend", help="Show evidence-based role recommendations from completed benchmarks.")
    def recommend(
        ctx: typer.Context,
        json_output: bool = typer.Option(False, "--json"),
    ):
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        rows = ModelBenchmarkService(state.settings).recommendations()
        payload = {
            "recommendations": rows,
            "evidence_required": True,
            "message": (
                "No completed benchmarks are available; run `redteam models benchmark MODEL`."
                if not rows
                else "Recommendations use the best completed local benchmark per model and role."
            ),
        }
        if state.json_output:
            emit_envelope(state, "models.recommend", payload)
        else:
            state.console.print(
                data_table(
                    "Model recommendations",
                    ["Model", "Role", "Level", "Score", "Evidence"],
                    [
                        (
                            row.get("model"),
                            row.get("role"),
                            row.get("level"),
                            row.get("score"),
                            "; ".join(row.get("evidence") or []),
                        )
                        for row in rows
                    ],
                )
            )
            if not rows:
                state.console.print(payload["message"])

    @models_app.command("benchmark-list", help="List separate adaptive benchmark artifacts.")
    def benchmark_list(
        ctx: typer.Context,
        json_output: bool = typer.Option(False, "--json"),
    ):
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        rows = ModelBenchmarkService(state.settings).list()
        if state.json_output:
            emit_envelope(state, "models.benchmark-list", rows)
        else:
            state.console.print(
                data_table(
                    "Benchmarks",
                    ["ID", "Created", "Dataset", "Models", "Status"],
                    [
                        (
                            row["benchmark_id"],
                            row.get("created_at"),
                            row.get("dataset_version"),
                            ", ".join(row.get("models") or []),
                            row.get("status"),
                        )
                        for row in rows
                    ],
                )
            )

    @models_app.command("benchmark-show", help="Show one adaptive benchmark report.")
    def benchmark_show(
        ctx: typer.Context,
        benchmark_id: str = typer.Argument(..., metavar="BENCHMARK_ID"),
        json_output: bool = typer.Option(False, "--json"),
    ):
        state = _state(ctx)
        state.json_output = state.json_output or json_output
        payload = ModelBenchmarkService(state.settings).show(benchmark_id)
        if state.json_output:
            emit_envelope(state, "models.benchmark-show", payload)
        else:
            state.console.print(details_table("Benchmark report", payload.items()))
