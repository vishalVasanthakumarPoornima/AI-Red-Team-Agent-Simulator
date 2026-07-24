"""Capability derivation from configured endpoints and correlated inventory."""

from __future__ import annotations

from redteam_platform.dexter.models import (
    DexterCapability,
    DexterComponent,
    DexterComponentStatus,
    DexterComponentType,
    DexterConfiguration,
)


def configured_components(configuration: DexterConfiguration) -> list[DexterComponent]:
    components = [
        DexterComponent(
            stable_id="dexter_component_api",
            name="Dexter API",
            component_type=DexterComponentType.API,
            endpoint=configuration.main_endpoint,
            required=True,
            evidence=[f"configured by {configuration.source}"],
        ),
        DexterComponent(
            stable_id="dexter_component_reports",
            name="Run artifact directory",
            component_type=DexterComponentType.REPORTS,
            required=True,
            evidence=["Phase 1 artifact store"],
        ),
    ]
    optional = (
        ("ollama", DexterComponentType.OLLAMA, configuration.ollama_endpoint),
        ("memory", DexterComponentType.MEMORY, configuration.memory_endpoint),
        ("vector", DexterComponentType.VECTOR, configuration.vector_endpoint),
        ("retrieval", DexterComponentType.RETRIEVAL, configuration.retrieval_endpoint),
    )
    for name, component_type, endpoint in optional:
        components.append(
            DexterComponent(
                stable_id=f"dexter_component_{name}",
                name=name.title(),
                component_type=component_type,
                endpoint=endpoint,
                status=(
                    DexterComponentStatus.UNKNOWN
                    if endpoint
                    else DexterComponentStatus.NOT_CONFIGURED
                ),
                evidence=["explicit endpoint configuration"] if endpoint else [],
            )
        )
    for index, endpoint in enumerate(configuration.tool_endpoints, 1):
        components.append(
            DexterComponent(
                stable_id=f"dexter_component_tool_{index}",
                name=f"Tool service {index}",
                component_type=DexterComponentType.TOOL,
                endpoint=endpoint,
                evidence=["explicit endpoint configuration"],
            )
        )
    for index, endpoint in enumerate(configuration.voice_endpoints, 1):
        components.append(
            DexterComponent(
                stable_id=f"dexter_component_voice_{index}",
                name=f"Voice service {index}",
                component_type=DexterComponentType.VOICE,
                endpoint=endpoint,
                evidence=["explicit endpoint configuration"],
            )
        )
    return components


def capabilities_for(
    configuration: DexterConfiguration,
    components: list[DexterComponent],
) -> list[DexterCapability]:
    component_types = {
        component.component_type
        for component in components
        if component.status != DexterComponentStatus.NOT_CONFIGURED
    }
    return [
        DexterCapability(name="api", available=True, source="configuration"),
        DexterCapability(name="chat", available=True, source="configuration"),
        DexterCapability(name="openapi", available=True, source="configuration"),
        DexterCapability(
            name="tools",
            available=DexterComponentType.TOOL in component_types,
            source="configuration",
        ),
        DexterCapability(
            name="memory",
            available=DexterComponentType.MEMORY in component_types,
            source="configuration",
            details={"disposable_namespace": configuration.disposable_memory_namespace},
        ),
        DexterCapability(
            name="retrieval",
            available=bool(
                component_types
                & {DexterComponentType.RETRIEVAL, DexterComponentType.VECTOR}
            ),
            source="configuration",
        ),
        DexterCapability(
            name="ollama",
            available=DexterComponentType.OLLAMA in component_types,
            source="configuration",
            details={"expected_model": configuration.expected_model},
        ),
        DexterCapability(
            name="voice",
            available=DexterComponentType.VOICE in component_types,
            source="configuration",
        ),
    ]
