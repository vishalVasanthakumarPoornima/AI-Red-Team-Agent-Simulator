import json
import os
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from click.utils import strip_ansi
from typer.testing import CliRunner

from redteam_platform import __version__
from redteam_platform.cli import app
from redteam_platform.cli.app import _propagate_exit_code
from redteam_platform.cli.exit_codes import ExitCode
from redteam_platform.cli.queries import InventoryQuery
from redteam_platform.diagnostics import DiagnosticResult
from redteam_platform.inventory import InventoryService
from redteam_platform.inventory.models import (
    AdapterRun,
    AdapterState,
    AgentDescriptor,
    DiscoveryConfidence,
    DiscoverySource,
    HealthState,
    InventorySnapshot,
    InventoryStatus,
    InventorySummary,
    ItemType,
    Listener,
    OllamaModel,
)
from redteam_platform.run_browser import RunBrowser
from redteam_platform.schemas import ScopeClassification
from redteam_platform.settings import Settings


def sample_snapshot() -> InventorySnapshot:
    agent = AgentDescriptor(
        stable_id="python_target_demo",
        name="demo",
        item_type=ItemType.PYTHON_TARGET,
        status=InventoryStatus.READY,
        endpoint="python://demo",
        local_path="targets/demo.py",
        discovery_source=DiscoverySource.TARGET_MARKER,
        discovery_confidence=DiscoveryConfidence.CONFIRMED,
        health=HealthState.HEALTHY,
        scope_classification=ScopeClassification.LOOPBACK,
        agent_kind="python_target",
        enrolled=True,
    )
    model = OllamaModel(
        stable_id="model_demo",
        name="demo:latest",
        endpoint="http://127.0.0.1:11434",
        discovery_source=DiscoverySource.OLLAMA_API,
        discovery_confidence=DiscoveryConfidence.CONFIRMED,
        scope_classification=ScopeClassification.LOOPBACK,
        endpoint_id="ollama_local",
        model_name="demo:latest",
        installed=True,
        running=False,
    )
    listener = Listener(
        stable_id="listener_demo",
        name="python",
        status=InventoryStatus.ACTIVE,
        endpoint="tcp://127.0.0.1:18080",
        host="127.0.0.1",
        port=18080,
        protocol="tcp",
        discovery_source=DiscoverySource.PSUTIL,
        discovery_confidence=DiscoveryConfidence.HIGH,
        scope_classification=ScopeClassification.LOOPBACK,
        address="127.0.0.1",
        transport="tcp",
        loopback_only=True,
        wildcard_bound=False,
    )
    return InventorySnapshot(
        items=[agent, model, listener],
        adapter_runs=[
            AdapterRun(
                adapter="synthetic",
                state=AdapterState.SUCCESS,
                duration_seconds=0,
                item_count=3,
            )
        ],
        summary=InventorySummary(
            installed_ollama_models=1,
            running_ollama_models=0,
            enrolled_python_targets=1,
            generic_listening_services=1,
        ),
    )


class CLIEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_help_and_versions(self):
        result = self.runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        help_text = strip_ansi(result.stdout)
        self.assertIn("inventory", help_text)
        self.assertIn("--non-interactive", help_text)
        self.assertIn("Configuration:", help_text)
        self.assertIn("Environment:", help_text)
        self.assertIn("Common workflow:", help_text)
        self.assertIn("redteam help", help_text)
        self.assertIn("GROUP COMMAND", help_text)
        self.assertEqual(self.runner.invoke(app, ["-h"]).exit_code, 0)
        self.assertEqual(self.runner.invoke(app, ["--version"]).exit_code, 0)
        payload = json.loads(self.runner.invoke(app, ["version", "--json"]).stdout)
        self.assertEqual(payload["command"], "version")

    def test_help_command_routes_to_top_level_and_nested_commands(self):
        doctor = self.runner.invoke(app, ["help", "doctor"])
        self.assertEqual(doctor.exit_code, 0, doctor.output)
        doctor_help = strip_ansi(doctor.stdout)
        self.assertIn("Usage: redteam doctor", doctor_help)
        self.assertIn("redteam doctor --strict", doctor_help)

        nested = self.runner.invoke(app, ["help", "assess", "run"])
        self.assertEqual(nested.exit_code, 0, nested.output)
        nested_help = strip_ansi(nested.stdout)
        self.assertIn("Usage: redteam assess run", nested_help)
        self.assertIn("redteam assess run python://tool_agent", nested_help)

    def test_invalid_help_path_and_invalid_command_are_actionable(self):
        missing_help = self.runner.invoke(app, ["help", "not-a-command"])
        self.assertEqual(missing_help.exit_code, 2)
        missing_help_text = strip_ansi(missing_help.output)
        self.assertNotIn("Traceback", missing_help_text)
        self.assertIn("redteam --help", missing_help_text)

        invalid = self.runner.invoke(app, ["not-a-command"])
        self.assertEqual(invalid.exit_code, 2)
        invalid_text = strip_ansi(invalid.output)
        self.assertNotIn("Traceback", invalid_text)
        self.assertIn("-h' for help", invalid_text)

    def test_source_and_package_versions_match(self):
        pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["version"], __version__)

    def test_target_kind_alias_and_invalid_kind(self):
        alias = self.runner.invoke(
            app,
            ["targets", "parse", "tool_agent", "--kind", "python", "--json"],
        )
        self.assertEqual(alias.exit_code, 0, alias.output)
        self.assertEqual(json.loads(alias.stdout)["data"]["kind_hint"], "python_agent")

        invalid = self.runner.invoke(
            app,
            ["targets", "parse", "tool_agent", "--kind", "definitely-invalid"],
        )
        self.assertEqual(invalid.exit_code, 2)
        self.assertIn("Unsupported target kind", invalid.output)
        self.assertNotIn("Traceback", invalid.output)

    def test_console_entrypoint_propagates_nonzero_typer_exit(self):
        with self.assertRaises(SystemExit) as raised:
            _propagate_exit_code(int(ExitCode.ARTIFACT_FAILURE))
        self.assertEqual(raised.exception.code, int(ExitCode.ARTIFACT_FAILURE))
        self.assertIsNone(_propagate_exit_code(int(ExitCode.SUCCESS)))

    def test_no_args_non_tty_shows_help(self):
        result = self.runner.invoke(app, [])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Usage:", result.stdout)
        self.assertNotIn("Select:", result.stdout)

    def test_menu_exit_eof_and_invalid_selection(self):
        result = self.runner.invoke(app, ["menu"], input="99\n0\n")
        self.assertEqual(result.exit_code, 0)
        self.assertIn("AI Agent Red Team Simulator", result.stdout)
        self.assertIn("Exited safely", result.stdout)
        eof = self.runner.invoke(app, ["menu"], input="")
        self.assertEqual(eof.exit_code, 0)
        self.assertIn("Exited safely", eof.stdout)

    def test_menu_non_interactive_rejected(self):
        result = self.runner.invoke(app, ["--non-interactive", "menu"])
        self.assertNotEqual(result.exit_code, 0)

    def test_global_option_conflict(self):
        result = self.runner.invoke(app, ["--quiet", "--verbose", "version"])
        self.assertEqual(result.exit_code, 2)

    def test_no_color_and_help_topics(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            result = self.runner.invoke(app, ["help", "authorization"])
        self.assertEqual(result.exit_code, 0)
        self.assertNotIn("\x1b[", result.stdout)
        self.assertIn("--yes", result.stdout)

    def test_missing_authorization_json_error_and_exit(self):
        result = self.runner.invoke(
            app,
            [
                "--non-interactive",
                "assess",
                "start",
                "--kind",
                "python",
                "--target",
                "tool_agent",
                "--json",
            ],
        )
        self.assertEqual(result.exit_code, 4)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["success"])
        self.assertEqual(payload["errors"][0]["type"], "missing_authorization")
        self.assertIn("redteam help COMMAND", payload["errors"][0]["remediation"])
        self.assertNotIn("Traceback", result.stderr)

    def test_invalid_configuration_is_structured_in_global_json_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invalid.toml"
            path.write_text("[redteam\n")
            result = self.runner.invoke(
                app, ["--config", str(path), "--json", "doctor"]
            )
        self.assertEqual(result.exit_code, 3)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["errors"][0]["type"], "invalid_configuration")
        self.assertNotIn("Traceback", result.stderr)


class InventoryCommandTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()
        self.snapshot = sample_snapshot()

    def invoke(self, arguments):
        with patch(
            "redteam_platform.cli.commands.inventory._snapshot",
            return_value=self.snapshot,
        ):
            return self.runner.invoke(app, arguments)

    def test_summary_json_envelope(self):
        result = self.invoke(["inventory", "summary", "--json"])
        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["command"], "inventory.summary")
        self.assertEqual(payload["data"]["installed_ollama_models"], 1)
        self.assertNotIn("\x1b[", result.stdout)

    def test_human_tables(self):
        self.assertIn("AI agents", self.invoke(["agents", "list"]).stdout)
        self.assertIn("Ollama models", self.invoke(["models", "list"]).stdout)
        services = self.invoke(["services", "list"])
        self.assertIn("Services and listeners", services.stdout)
        self.assertNotIn("confirmed AI agent", services.stdout)

    def test_legacy_json_is_raw(self):
        result = self.invoke(["agents", "--json"])
        self.assertEqual(result.exit_code, 0)
        self.assertIsInstance(json.loads(result.stdout), list)

    def test_filters(self):
        result = self.invoke(["services", "list", "--port", "18080", "--json"])
        payload = json.loads(result.stdout)
        self.assertEqual(len(payload["data"]), 1)
        result = self.invoke(["models", "running", "--json"])
        self.assertEqual(json.loads(result.stdout)["data"], [])

    def test_show_missing_expected_error(self):
        result = self.invoke(["agents", "show", "missing"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertNotIn("Traceback", result.stderr)

    def test_query_utility(self):
        rows = InventoryQuery(port=18080, loopback=True).apply(self.snapshot.items)
        self.assertEqual([item.stable_id for item in rows], ["listener_demo"])
        self.assertEqual(InventoryQuery(running=True).apply(self.snapshot.items), [])

    def test_partial_inventory_query_does_not_replace_shared_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            service = InventoryService(
                Settings(
                    inventory_cache=Path(directory) / "inventory.json",
                    report_root=Path(directory) / "runs",
                )
            )
            with patch.object(service.cache, "write") as write:
                service.collect(
                    include_ollama=False,
                    include_listeners=False,
                    include_targets=False,
                    include_http=False,
                    include_docker=False,
                    include_kali=False,
                    persist_cache=False,
                )
            write.assert_not_called()


class ScopeAndAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_scope_allowed_loopback_json(self):
        result = self.runner.invoke(
            app, ["scope", "validate", "http://127.0.0.1:18080", "--json"]
        )
        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["data"]["allowed"])
        self.assertEqual(payload["data"]["classification"], "loopback")

    def test_scope_denied_public_and_credentials(self):
        public = self.runner.invoke(
            app, ["scope", "validate", "https://example.com", "--json"]
        )
        self.assertEqual(public.exit_code, 4)
        self.assertFalse(json.loads(public.stdout)["data"]["allowed"])
        credentials = self.runner.invoke(
            app,
            ["scope", "validate", "http://user:pass@127.0.0.1:8000", "--json"],
        )
        self.assertEqual(credentials.exit_code, 4)
        self.assertIn("Credential-bearing", credentials.stdout)

    def test_scope_explain_never_calls_executor(self):
        with patch("redteam_platform.service.ApplicationService.run") as execute:
            result = self.runner.invoke(
                app, ["scope", "explain", "http://127.0.0.1:18080"]
            )
        self.assertEqual(result.exit_code, 0)
        execute.assert_not_called()
        self.assertIn("human authorization", result.stdout)

    def test_assessment_plan_has_no_run_side_effect(self):
        with patch("redteam_platform.service.ApplicationService.run") as execute:
            result = self.runner.invoke(
                app,
                [
                    "assess",
                    "plan",
                    "--kind",
                    "python",
                    "--target",
                    "tool_agent",
                    "--authorization",
                    "I own this local synthetic target and authorize bounded testing.",
                    "--category",
                    "prompt_disclosure",
                    "--json",
                ],
            )
        self.assertEqual(result.exit_code, 0, result.stderr)
        execute.assert_not_called()
        payload = json.loads(result.stdout)
        self.assertEqual(payload["command"], "assess.plan")

    def test_dexter_routes_to_first_class_phase4_service(self):
        with (
            patch("redteam_platform.service.ApplicationService.run") as legacy_execute,
            patch(
                "redteam_platform.cli.commands.dexter.execute_assessment_command"
            ) as dexter_execute,
        ):
            result = self.runner.invoke(
                app,
                [
                    "assess",
                    "start",
                    "--kind",
                    "dexter",
                    "--target",
                    "http://127.0.0.1:8000",
                    "--authorization",
                    "I own this local target and authorize bounded testing.",
                    "--yes",
                    "--json",
                ],
            )
        self.assertEqual(result.exit_code, 0, result.stdout)
        legacy_execute.assert_not_called()
        dexter_execute.assert_called_once()

    def test_denied_target_never_reaches_executor(self):
        with patch("redteam_platform.service.ApplicationService.run") as execute:
            result = self.runner.invoke(
                app,
                [
                    "assess",
                    "start",
                    "--kind",
                    "http",
                    "--target",
                    "https://example.com",
                    "--authorization",
                    "I am authorized to test this target.",
                    "--json",
                ],
            )
        self.assertEqual(result.exit_code, 4)
        execute.assert_not_called()

    def test_wizard_cancel_has_no_executor_call(self):
        with patch("redteam_platform.service.ApplicationService.run") as execute:
            result = self.runner.invoke(app, ["assess"], input="0\n")
        self.assertEqual(result.exit_code, 0)
        execute.assert_not_called()


class RunBrowserTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.run_dir = self.root / "run_20260101T000000Z_demo"
        self.run_dir.mkdir()
        (self.run_dir / "summary.json").write_text(
            json.dumps(
                {
                    "run_id": self.run_dir.name,
                    "status": "complete",
                    "target_id": "python_demo",
                    "profile": "standard",
                    "started_at": "2026-01-01T00:00:00Z",
                    "ended_at": "2026-01-01T00:01:00Z",
                    "finding_counts": {"High": 1},
                    "errors": [],
                    "stop_reason": "complete",
                }
            )
        )
        (self.run_dir / "findings.json").write_text(
            json.dumps([{"id": "finding_1", "title": "Demo"}])
        )
        (self.run_dir / "authorization.json").write_text(
            json.dumps(
                {
                    "id": "auth_demo",
                    "statement": "secret human authorization statement",
                    "human_authorization_statement": "secret human authorization statement",
                }
            )
        )
        (self.run_dir / "events.jsonl").write_text(
            '{"sequence":1,"phase":"start","action":"plan","status":"ok"}\n'
        )
        (self.run_dir / "report.md").write_text("# Safe report\n")
        (self.run_dir / "report.json").write_text('{"safe":true}\n')
        (self.run_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "run_id": self.run_dir.name,
                    "status": "complete",
                    "scope": "python://demo",
                    "artifacts": [],
                }
            )
        )
        self.browser = RunBrowser(self.root)

    def tearDown(self):
        self.directory.cleanup()

    def test_list_show_events_and_artifacts(self):
        rows = self.browser.list()
        self.assertEqual(rows[0]["finding_count"], 1)
        shown = self.browser.show(self.run_dir.name)
        self.assertTrue(shown["authorization_summary"]["statement_present"])
        self.assertNotIn("statement", shown["authorization_summary"])
        self.assertEqual(len(self.browser.events(self.run_dir.name)), 1)
        self.assertTrue(self.browser.artifacts(self.run_dir.name))

    def test_corrupt_and_partial_run(self):
        corrupt = self.root / "run_corrupt"
        corrupt.mkdir()
        (corrupt / "summary.json").write_text("{")
        row = next(item for item in self.browser.list() if item["run_id"] == "run_corrupt")
        self.assertEqual(row["status"], "partial")
        self.assertTrue(row["integrity_warnings"])

    def test_export_refuses_overwrite_and_unavailable_format(self):
        destination = self.root / "export.md"
        exported = self.browser.export(
            self.run_dir.name, format="markdown", destination=destination
        )
        self.assertEqual(exported, destination)
        with self.assertRaises(FileExistsError):
            self.browser.export(
                self.run_dir.name, format="markdown", destination=destination
            )
        with self.assertRaises(ValueError):
            self.browser.export(self.run_dir.name, format="pdf")

    def test_traversal_is_rejected(self):
        with self.assertRaises(ValueError):
            self.browser.show("../run_escape")
        with self.assertRaises(ValueError):
            self.browser.show("run_../escape")

    def test_cli_run_and_report_json(self):
        with patch.dict(os.environ, {"REDTEAM_REPORT_ROOT": str(self.root)}):
            listed = CliRunner().invoke(app, ["runs", "list", "--json"])
            report = CliRunner().invoke(
                app, ["reports", "show", self.run_dir.name, "--json"]
            )
        self.assertEqual(listed.exit_code, 0)
        self.assertEqual(json.loads(listed.stdout)["data"][0]["run_id"], self.run_dir.name)
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(json.loads(report.stdout)["data"]["artifact"], "report.md")

    def test_missing_run_json_error_exit(self):
        with patch.dict(os.environ, {"REDTEAM_REPORT_ROOT": str(self.root)}):
            result = CliRunner().invoke(
                app, ["runs", "show", "run_missing", "--json"]
            )
        self.assertEqual(result.exit_code, 9)
        self.assertEqual(json.loads(result.stdout)["errors"][0]["type"], "artifact_error")


class DiagnosticsAndKaliTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_doctor_json_and_strict(self):
        results = [
            DiagnosticResult("required", "PASS", "ok"),
            DiagnosticResult("optional", "WARN", "missing", "install it"),
        ]
        with patch(
            "redteam_platform.cli.commands.doctor.DoctorService.run",
            return_value=results,
        ):
            normal = self.runner.invoke(app, ["doctor", "--json"])
            strict = self.runner.invoke(app, ["doctor", "--strict", "--json"])
        self.assertEqual(normal.exit_code, 0)
        self.assertEqual(strict.exit_code, 8)
        self.assertFalse(json.loads(strict.stdout)["success"])

    def test_kali_not_configured_without_live_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / "empty.env"
            env_file.write_text("", encoding="utf-8")
            result = self.runner.invoke(
                app,
                ["--env-file", str(env_file), "kali", "status", "--json"],
            )
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.stdout)["data"]
        self.assertEqual(data[0]["status"], "not_configured")
        self.assertFalse(data[0]["live_check_performed"])

    def test_kali_check_requires_live(self):
        result = self.runner.invoke(app, ["kali", "check"])
        self.assertEqual(result.exit_code, 2)

    def test_config_show_redacts_secrets(self):
        with patch.dict(os.environ, {"REDTEAM_API_TOKEN": "super-secret-value"}):
            result = self.runner.invoke(app, ["config", "show", "--json"])
        self.assertEqual(result.exit_code, 0)
        self.assertNotIn("super-secret-value", result.stdout)
        self.assertIn("REDACTED", result.stdout)

    def test_config_paths_and_validate(self):
        self.assertEqual(
            self.runner.invoke(app, ["config", "paths", "--json"]).exit_code, 0
        )
        self.assertEqual(
            self.runner.invoke(app, ["config", "validate", "--json"]).exit_code,
            0,
        )


if __name__ == "__main__":
    unittest.main()
