"""Deterministic adapter registration and resolution metadata."""

from __future__ import annotations

from redteam_platform.schemas import AssessmentProfile
from redteam_platform.targets.models import AdapterMetadata, TargetDescriptor, TargetKind


ADAPTER_METADATA = (
    AdapterMetadata(
        adapter_name="dexter_bridge",
        supported_kinds=[TargetKind.DEXTER],
        supported_profiles=list(AssessmentProfile),
        passive_capabilities=["specialized_discovery", "readiness", "openapi"],
        active_capabilities=["dexter_deterministic_assessment"],
        required_tools=["dexter_phase4"],
        maximum_requests=80,
        timeout_seconds=600,
    ),
    AdapterMetadata(
        adapter_name="python_agent",
        supported_kinds=[TargetKind.PYTHON_AGENT],
        supported_profiles=list(AssessmentProfile),
        passive_capabilities=["enrollment", "import_health"],
        active_capabilities=["ai_prompts"],
        required_tools=["python_target_contract"],
        maximum_requests=24,
        timeout_seconds=300,
    ),
    AdapterMetadata(
        adapter_name="http_agent",
        supported_kinds=[TargetKind.HTTP_AGENT],
        supported_profiles=list(AssessmentProfile),
        passive_capabilities=["health", "metadata", "openapi"],
        active_capabilities=["ai_prompts", "api_inputs"],
        required_tools=["http"],
        maximum_requests=30,
        timeout_seconds=300,
    ),
    AdapterMetadata(
        adapter_name="openai_compatible",
        supported_kinds=[TargetKind.OPENAI_COMPATIBLE],
        supported_profiles=list(AssessmentProfile),
        passive_capabilities=["models", "authentication"],
        active_capabilities=["chat_completions"],
        required_tools=["http"],
        maximum_requests=20,
        timeout_seconds=300,
    ),
    AdapterMetadata(
        adapter_name="ollama",
        supported_kinds=[TargetKind.OLLAMA_ENDPOINT, TargetKind.OLLAMA_AGENT],
        supported_profiles=list(AssessmentProfile),
        passive_capabilities=["installed_models", "running_models", "version"],
        active_capabilities=["selected_model_invocation"],
        required_tools=["http"],
        maximum_requests=20,
        timeout_seconds=300,
    ),
    AdapterMetadata(
        adapter_name="web",
        supported_kinds=[TargetKind.WEBSITE, TargetKind.WEB_APPLICATION],
        supported_profiles=list(AssessmentProfile),
        passive_capabilities=["http", "headers", "cookies", "tls"],
        active_capabilities=["bounded_web_inputs"],
        required_tools=["http", "tls"],
        maximum_requests=30,
        timeout_seconds=300,
    ),
    AdapterMetadata(
        adapter_name="host",
        supported_kinds=[TargetKind.HOST, TargetKind.IP_ADDRESS],
        supported_profiles=list(AssessmentProfile),
        passive_capabilities=["scope", "inventory_correlation"],
        active_capabilities=["approved_port_connectivity", "http_handoff", "tls_handoff"],
        required_tools=["socket"],
        maximum_requests=16,
        timeout_seconds=180,
    ),
    AdapterMetadata(
        adapter_name="local_service",
        supported_kinds=[TargetKind.LOCAL_SERVICE],
        supported_profiles=[AssessmentProfile.PASSIVE, AssessmentProfile.STANDARD],
        passive_capabilities=["inventory", "binding", "process_relationship"],
        active_capabilities=["protocol_specific_only"],
        maximum_requests=4,
        timeout_seconds=60,
    ),
)


class TargetAdapterRegistry:
    def __init__(self, metadata: tuple[AdapterMetadata, ...] = ADAPTER_METADATA):
        self._metadata = metadata

    def list(self) -> list[AdapterMetadata]:
        return list(self._metadata)

    def resolve(self, target: TargetDescriptor) -> AdapterMetadata:
        matches = [
            item for item in self._metadata if target.target_kind in item.supported_kinds
        ]
        if not matches:
            raise LookupError(f"No adapter supports target kind {target.target_kind}.")
        if len(matches) > 1:
            raise LookupError(
                f"Ambiguous adapter resolution for {target.target_kind}: "
                + ", ".join(item.adapter_name for item in matches)
            )
        return matches[0]

    def create(self, target: TargetDescriptor):
        from redteam_platform.targets.adapters import (
            DexterBridgeAdapter,
            RegisteredTargetAdapter,
        )

        metadata = self.resolve(target)
        adapter_type = (
            DexterBridgeAdapter
            if metadata.adapter_name == "dexter_bridge"
            else RegisteredTargetAdapter
        )
        return adapter_type(metadata)
