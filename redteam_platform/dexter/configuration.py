"""Dexter configuration projection and scope-safe endpoint expansion."""

from __future__ import annotations

from urllib.parse import urljoin

from redteam_platform.dexter.models import DexterConfiguration, DexterProfile
from redteam_platform.settings import DexterSettings, Settings


def configuration_from_settings(value: DexterSettings, *, source: str) -> DexterConfiguration:
    return DexterConfiguration(
        name=value.name,
        main_endpoint=value.api_endpoint,
        health_route=value.health_path,
        chat_route=value.chat_path,
        metadata_route=value.metadata_path,
        openapi_route=value.openapi_path,
        authentication_mode=value.authentication_mode,
        authentication_reference=value.authentication_reference,
        ollama_endpoint=value.ollama_endpoint,
        expected_model=value.expected_model,
        tool_endpoints=value.tool_endpoints,
        memory_endpoint=value.memory_endpoint,
        vector_endpoint=value.vector_endpoint,
        retrieval_endpoint=value.retrieval_endpoint,
        voice_endpoints=value.voice_endpoints,
        docker_names=value.docker_names,
        docker_labels=value.docker_labels,
        expected_ports=value.expected_ports,
        requires_kali_tunnel=value.requires_kali_tunnel,
        kali_remote_port=value.kali_remote_port,
        allowed_profiles=[DexterProfile(profile) for profile in value.allowed_profiles],
        disposable_memory_namespace=value.disposable_memory_namespace,
        source=source,
    )


def configured_deployments(settings: Settings) -> list[DexterConfiguration]:
    values = [configuration_from_settings(settings.dexter, source="redteam.dexter")]
    values.extend(
        configuration_from_settings(item, source=f"redteam.dexter_deployments[{index}]")
        for index, item in enumerate(settings.dexter_deployments)
    )
    unique: dict[tuple[str, str], DexterConfiguration] = {}
    for value in values:
        unique[(value.name.lower(), value.main_endpoint)] = value
    return list(unique.values())


def endpoint_map(configuration: DexterConfiguration) -> dict[str, str]:
    base = configuration.main_endpoint.rstrip("/") + "/"
    endpoints = {
        "main": configuration.main_endpoint,
        "health": urljoin(base, configuration.health_route.lstrip("/")),
        "chat": urljoin(base, configuration.chat_route.lstrip("/")),
        "metadata": urljoin(base, configuration.metadata_route.lstrip("/")),
        "openapi": urljoin(base, configuration.openapi_route.lstrip("/")),
    }
    optional = {
        "ollama": configuration.ollama_endpoint,
        "memory": configuration.memory_endpoint,
        "vector": configuration.vector_endpoint,
        "retrieval": configuration.retrieval_endpoint,
    }
    endpoints.update({key: value for key, value in optional.items() if value})
    for index, value in enumerate(configuration.tool_endpoints):
        endpoints[f"tool_{index + 1}"] = value
    for index, value in enumerate(configuration.voice_endpoints):
        endpoints[f"voice_{index + 1}"] = value
    return endpoints
