import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from redteam_platform.artifacts import RunArtifacts, sanitize, sanitize_url
from redteam_platform.schemas import AssessmentProfile
from redteam_platform.schemas import CoverageState, ResultStatus, RunSummary, utc_now
from redteam_platform.scope_policy import ScopePolicy
from redteam_platform.settings import Settings


class ArtifactTests(unittest.TestCase):
    def test_sensitive_fields_and_urls_are_redacted(self):
        value = sanitize(
            {
                "api_token": "do-not-store",
                "endpoint": "https://user:secret@example.com/path?q=secret",
                "Authorization": "Bearer private",
            }
        )
        self.assertEqual(value["api_token"], "<REDACTED>")
        self.assertEqual(value["endpoint"], "https://example.com/path")
        self.assertEqual(value["Authorization"], "<REDACTED>")
        self.assertEqual(sanitize_url("https://example.com/a?x=1"), "https://example.com/a")

    def test_manifest_hashes_written_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = RunArtifacts(directory, run_id="run_test")
            artifacts.write_json("example.json", {"value": 1})
            manifest = artifacts.build_manifest()
            self.assertEqual(manifest.artifacts[0].path, "example.json")
            parsed = json.loads((Path(directory) / "run_test" / "manifest.json").read_text())
            self.assertEqual(parsed["run_id"], "run_test")

    def test_manifest_records_lifecycle_tools_models_scope_and_errors(self):
        record = ScopePolicy(Settings()).authorize(
            "python://fixture",
            statement="I own this local fixture and authorize bounded active testing.",
            source="human-cli",
            profile=AssessmentProfile.STANDARD,
        )
        started = utc_now()
        summary = RunSummary(
            run_id="run_manifest",
            status=ResultStatus.ERROR,
            target_id="fixture",
            profile=AssessmentProfile.STANDARD,
            started_at=started,
            ended_at=utc_now(),
            coverage=CoverageState(),
            errors=["synthetic error"],
            stop_reason="synthetic stop",
        )
        with tempfile.TemporaryDirectory() as directory:
            artifacts = RunArtifacts(directory, run_id="run_manifest")
            artifacts.write_authorization(record)
            artifacts.write_json("findings.json", [])
            manifest = artifacts.build_manifest(
                summary=summary,
                authorization=record,
                tools=["unit-test-tool"],
                models=["unit-test-model"],
            )
            mode = stat.S_IMODE(artifacts.run_dir.stat().st_mode)
        self.assertEqual(manifest.status, "ERROR")
        self.assertEqual(manifest.stop_reason, "synthetic stop")
        self.assertEqual(manifest.tools, ["unit-test-tool"])
        self.assertEqual(manifest.models, ["unit-test-model"])
        self.assertEqual(manifest.scope, "python://fixture")
        self.assertEqual(manifest.errors, ["synthetic error"])
        self.assertEqual(mode & 0o077, 0)

    def test_unique_directories_and_existing_run_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            first = RunArtifacts(directory)
            second = RunArtifacts(directory)
            self.assertNotEqual(first.run_id, second.run_id)
            marker = first.write_json("findings.json", {"original": True})
            with self.assertRaises(FileExistsError):
                RunArtifacts(directory, run_id=first.run_id)
            self.assertEqual(json.loads(marker.read_text()), {"original": True})

    def test_atomic_write_failure_preserves_previous_json(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = RunArtifacts(directory, run_id="run_atomic")
            path = artifacts.write_json("findings.json", {"version": 1})
            with patch("redteam_platform.artifacts.os.replace", side_effect=OSError("synthetic")):
                with self.assertRaises(OSError):
                    artifacts.write_json("findings.json", {"version": 2})
            self.assertEqual(json.loads(path.read_text()), {"version": 1})
            self.assertEqual(list(artifacts.run_dir.glob("*.tmp")), [])

    def test_authorization_record_is_complete_and_sanitized(self):
        record = ScopePolicy(Settings()).authorize(
            "http://127.0.0.1:8000/path?token=private",
            statement="I own this service and authorize testing; token=do-not-persist",
            source="human-cli",
            profile=AssessmentProfile.STANDARD,
        )
        with tempfile.TemporaryDirectory() as directory:
            artifacts = RunArtifacts(directory, run_id="run_auth")
            path = artifacts.write_authorization(record)
            payload = json.loads(path.read_text())
        self.assertEqual(payload["run_id"], "run_auth")
        self.assertEqual(payload["normalized_target"], "http://127.0.0.1:8000/path")
        self.assertEqual(payload["requested_profile"], "standard")
        self.assertEqual(payload["scope_classification"], "loopback")
        self.assertIn("<REDACTED>", payload["human_authorization_statement"])
        self.assertNotIn("do-not-persist", json.dumps(payload))
        self.assertNotIn("private", json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
