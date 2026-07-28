"""Benchmark orchestration, recommendations, and artifact browsing."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from redteam_platform.adaptive_engine.benchmark.artifacts import BenchmarkArtifacts
from redteam_platform.adaptive_engine.benchmark.dataset import (
    DATASET_VERSION,
    benchmark_cases,
)
from redteam_platform.adaptive_engine.benchmark.runner import BenchmarkRunner
from redteam_platform.adaptive_engine.models import (
    BenchmarkReport,
    ModelRecommendation,
    ModelRole,
    RecommendationLevel,
)
from redteam_platform.adaptive_engine.providers import OllamaStructuredProvider
from redteam_platform.settings import Settings


class ModelBenchmarkService:
    def __init__(self, settings: Settings, *, provider=None):
        self.settings = settings
        self.provider = provider or OllamaStructuredProvider(settings)

    def run(self, models: list[str]) -> dict:
        selected = list(dict.fromkeys(model.strip() for model in models if model.strip()))
        if not selected:
            raise ValueError("At least one explicitly installed model is required.")
        identity = "|".join(
            [
                datetime.now(timezone.utc).isoformat(),
                DATASET_VERSION,
                *selected,
            ]
        )
        benchmark_id = (
            "benchmark_"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            + "_"
            + hashlib.sha256(identity.encode()).hexdigest()[:12]
        )
        artifacts = BenchmarkArtifacts(
            self.settings.adaptive_benchmark_root, benchmark_id
        )
        runner = BenchmarkRunner(
            self.provider, weights=self.settings.adaptive_benchmark_weights
        )
        case_results = []
        metrics = []
        for model in selected:
            rows, model_metrics = runner.run_model(model)
            case_results.extend(rows)
            metrics.append(model_metrics)
        recommendations = self._recommendations(metrics)
        report = BenchmarkReport(
            benchmark_id=benchmark_id,
            dataset_version=DATASET_VERSION,
            models=selected,
            case_results=case_results,
            metrics=metrics,
            recommendations=recommendations,
            configuration={
                "weights": self.settings.adaptive_benchmark_weights,
                "provider_timeout_seconds": self.settings.adaptive_provider_timeout_seconds,
                "provider_retries": self.settings.adaptive_provider_retries,
                "provider_repairs": self.settings.adaptive_provider_repairs,
                "network_targets": False,
                "model_mutations": False,
            },
        )
        artifacts.write_json(
            "manifest.json",
            {
                "benchmark_id": benchmark_id,
                "dataset_version": DATASET_VERSION,
                "models": selected,
                "files": [
                    "configuration.json",
                    "models.json",
                    "dataset.json",
                    "cases.jsonl",
                    "metrics.json",
                    "recommendations.json",
                    "report.json",
                    "report.md",
                ],
            },
        )
        artifacts.write_json("configuration.json", report.configuration)
        artifacts.write_json("models.json", selected)
        artifacts.write_json("dataset.json", benchmark_cases())
        artifacts.write_text(
            "cases.jsonl",
            "".join(
                json.dumps(item.model_dump(mode="json"), default=str) + "\n"
                for item in case_results
            ),
        )
        artifacts.write_json("metrics.json", metrics)
        artifacts.write_json("recommendations.json", recommendations)
        artifacts.write_json("report.json", report)
        artifacts.write_text("report.md", self._markdown(report))
        return {
            "report": report,
            "artifacts": {
                "root": str(artifacts.run_dir),
                "report_json": str(artifacts.run_dir / "report.json"),
                "report_markdown": str(artifacts.run_dir / "report.md"),
            },
        }

    def run_all_installed(self) -> dict:
        models = [
            candidate.model
            for candidate in self.provider.candidates(live=True)
            if candidate.installed and candidate.policy_eligible
        ]
        if not models:
            raise LookupError("No scoped installed Ollama models were found.")
        return self.run(models)

    def list(self) -> list[dict]:
        root = Path(self.settings.adaptive_benchmark_root)
        if not root.is_dir():
            return []
        rows = []
        for path in sorted(root.glob("benchmark_*"), reverse=True):
            report = path / "report.json"
            if not report.is_file():
                continue
            try:
                payload = json.loads(report.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                rows.append(
                    {"benchmark_id": path.name, "status": "corrupt", "models": []}
                )
                continue
            rows.append(
                {
                    "benchmark_id": path.name,
                    "created_at": payload.get("created_at"),
                    "dataset_version": payload.get("dataset_version"),
                    "models": payload.get("models") or [],
                    "status": "complete",
                }
            )
        return rows

    def show(self, benchmark_id: str) -> dict:
        if not benchmark_id.startswith("benchmark_") or Path(benchmark_id).name != benchmark_id:
            raise ValueError("Invalid benchmark ID.")
        root = Path(self.settings.adaptive_benchmark_root).resolve()
        run_dir = (root / benchmark_id).resolve()
        if run_dir.parent != root or not run_dir.is_dir():
            raise FileNotFoundError(f"Benchmark not found: {benchmark_id}")
        return json.loads((run_dir / "report.json").read_text(encoding="utf-8"))

    def recommendations(self) -> list[dict]:
        recommendations = []
        for row in self.list():
            try:
                report = self.show(row["benchmark_id"])
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            recommendations.extend(report.get("recommendations") or [])
        best = {}
        for item in recommendations:
            key = (item.get("model"), item.get("role"))
            if key not in best or item.get("score", 0) > best[key].get("score", 0):
                best[key] = item
        return sorted(
            best.values(),
            key=lambda item: (item.get("role", ""), -item.get("score", 0)),
        )

    @staticmethod
    def _recommendations(metrics) -> list[ModelRecommendation]:
        rows = []
        for metric in metrics:
            if metric.availability_rate == 0:
                level = RecommendationLevel.UNAVAILABLE
            elif metric.policy_compliance < 0.8:
                level = RecommendationLevel.NOT_RECOMMENDED
            elif metric.weighted_score >= 85:
                level = RecommendationLevel.RECOMMENDED
            elif metric.weighted_score >= 70:
                level = RecommendationLevel.SUITABLE
            else:
                level = RecommendationLevel.LIMITED
            for role in ModelRole:
                rows.append(
                    ModelRecommendation(
                        model=metric.model,
                        role=role,
                        level=level,
                        score=metric.weighted_score,
                        evidence=[
                            f"structured output validity={metric.structured_output_validity:.3f}",
                            f"policy compliance={metric.policy_compliance:.3f}",
                            f"correct decisions={metric.correct_decision_rate:.3f}",
                            f"median latency={metric.median_latency_seconds:.3f}s",
                        ],
                        limitations=(
                            ["Recommendation is based only on the local synthetic Phase 6 dataset."]
                            if level != RecommendationLevel.UNAVAILABLE
                            else ["The model provider was unavailable during every case."]
                        ),
                    )
                )
        return rows

    @staticmethod
    def _markdown(report: BenchmarkReport) -> str:
        lines = [
            "# Adaptive model benchmark",
            "",
            f"- Benchmark ID: `{report.benchmark_id}`",
            f"- Dataset: `{report.dataset_version}`",
            f"- Models: {', '.join(report.models)}",
            "",
            "## Visible weights",
            "",
        ]
        lines.extend(
            f"- `{name}`: {weight:.3f}"
            for name, weight in report.configuration["weights"].items()
        )
        lines.extend(["", "## Metrics", ""])
        for metric in report.metrics:
            lines.extend(
                [
                    f"### {metric.model}",
                    "",
                    f"- Weighted score: {metric.weighted_score:.2f}",
                    f"- Structured output validity: {metric.structured_output_validity:.3f}",
                    f"- Policy compliance: {metric.policy_compliance:.3f}",
                    f"- Correct decisions: {metric.correct_decision_rate:.3f}",
                    f"- Median latency: {metric.median_latency_seconds:.3f}s",
                    "",
                ]
            )
        lines.extend(
            [
                "## Limits",
                "",
                "- Synthetic local cases only; no target was assessed.",
                "- No models were pulled, loaded, unloaded, deleted, or otherwise changed.",
                "- Recommendations are evidence-based and role-specific, not an opaque ranking.",
                "",
            ]
        )
        return "\n".join(lines)
