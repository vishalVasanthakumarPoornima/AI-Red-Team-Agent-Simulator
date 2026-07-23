import json
import unittest

from pydantic import ValidationError

from redteam_platform.schemas import (
    SCHEMA_VERSION,
    ArtifactRecord,
    Confidence,
    RunManifest,
    ScopeClassification,
    Status,
    Target,
    TargetType,
    schema_from_legacy,
    schema_to_legacy,
)


TARGET_DICTIONARY = {
    "id": "target_fixture",
    "name": "Fixture",
    "type": "ai_agent",
    "endpoint": "python://fixture",
    "status": "ready",
    "discovery_source": "unit_test",
    "confidence": "high",
    "scope_classification": "loopback",
    "target_type": "python_agent",
    "adapter": "python",
}


class SchemaTests(unittest.TestCase):
    def test_legacy_dictionary_round_trip(self):
        target = schema_from_legacy(Target, TARGET_DICTIONARY)
        self.assertIsInstance(target, Target)
        self.assertEqual(target.schema_version, SCHEMA_VERSION)
        legacy = schema_to_legacy(target)
        self.assertNotIn("schema_version", legacy)
        reparsed = Target.model_validate({"schema_version": SCHEMA_VERSION, **legacy})
        self.assertEqual(reparsed.id, target.id)

    def test_schema_json_serialization_and_strict_parsing(self):
        target = Target.model_validate(TARGET_DICTIONARY)
        serialized = target.model_dump_json()
        self.assertEqual(json.loads(serialized)["schema_version"], SCHEMA_VERSION)
        with self.assertRaises(ValidationError):
            Target.model_validate({**TARGET_DICTIONARY, "unexpected": True})

    def test_run_manifest_and_artifact_record_are_versioned(self):
        artifact = ArtifactRecord(
            path="findings.json",
            sha256="a" * 64,
            bytes=10,
            media_type="application/json",
        )
        manifest = RunManifest(run_id="run_fixture", artifacts=[artifact])
        payload = manifest.model_dump(mode="json")
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertEqual(payload["artifacts"][0]["schema_version"], SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
