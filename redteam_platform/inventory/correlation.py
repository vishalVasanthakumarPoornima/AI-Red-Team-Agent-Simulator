"""Deterministic inventory correlation without model inference."""

from __future__ import annotations

from collections import defaultdict

from redteam_platform.inventory.models import (
    AgentDescriptor,
    CorrelationRecord,
    DiscoveryConfidence,
    DockerContainer,
    InventoryItem,
    Listener,
    OllamaEndpoint,
    ServiceEndpoint,
)
from redteam_platform.inventory.platform import normalize_identity_url, stable_id


def deduplicate(items: list[InventoryItem]) -> list[InventoryItem]:
    by_id: dict[str, InventoryItem] = {}
    for item in items:
        existing = by_id.get(item.stable_id)
        if existing is None:
            by_id[item.stable_id] = item
            continue
        existing.capabilities = sorted(set(existing.capabilities + item.capabilities))
        existing.evidence.extend(
            evidence for evidence in item.evidence if evidence not in existing.evidence
        )
        existing.errors.extend(error for error in item.errors if error not in existing.errors)
        existing.related_ids = sorted(set(existing.related_ids + item.related_ids))
        existing.last_seen = max(existing.last_seen, item.last_seen)
    return list(by_id.values())


class InventoryCorrelator:
    def correlate(
        self, items: list[InventoryItem]
    ) -> tuple[list[InventoryItem], list[CorrelationRecord]]:
        items = deduplicate(items)
        by_id = {item.stable_id: item for item in items}
        correlations: list[CorrelationRecord] = []

        services = [item for item in items if isinstance(item, ServiceEndpoint)]
        listeners = [
            item
            for item in items
            if isinstance(item, Listener)
            and item.network_namespace in {None, "host"}
        ]
        agents = [item for item in items if isinstance(item, AgentDescriptor)]
        ollama = [item for item in items if isinstance(item, OllamaEndpoint)]
        containers = [item for item in items if isinstance(item, DockerContainer)]

        listeners_by_port: dict[int, list[Listener]] = defaultdict(list)
        for listener in listeners:
            if listener.port:
                listeners_by_port[listener.port].append(listener)

        for service in services:
            candidates = listeners_by_port.get(service.port or -1, [])
            compatible = [
                listener
                for listener in candidates
                if listener.protocol == "tcp"
                and (
                    listener.loopback_only
                    or listener.wildcard_bound
                    or listener.host == service.host
                )
            ]
            if len(compatible) == 1:
                self._record(
                    correlations,
                    by_id,
                    [service.stable_id, compatible[0].stable_id],
                    logical_name=service.name,
                    confidence=DiscoveryConfidence.HIGH,
                    reasons=["HTTP endpoint port matches one host-network TCP listener."],
                )

        for agent in agents:
            if agent.service_endpoint_id and agent.service_endpoint_id in by_id:
                self._record(
                    correlations,
                    by_id,
                    [agent.stable_id, agent.service_endpoint_id],
                    logical_name=agent.name,
                    confidence=DiscoveryConfidence.CONFIRMED,
                    reasons=["Agent metadata explicitly references the discovered service endpoint."],
                )
                continue
            if not agent.endpoint:
                continue
            matches = [
                service
                for service in services
                if normalize_identity_url(service.endpoint or "")
                == normalize_identity_url(agent.endpoint or "")
            ]
            if len(matches) == 1:
                confidence = (
                    DiscoveryConfidence.HIGH
                    if agent.registered
                    else DiscoveryConfidence.MEDIUM
                )
                self._record(
                    correlations,
                    by_id,
                    [agent.stable_id, matches[0].stable_id],
                    logical_name=agent.name,
                    confidence=confidence,
                    reasons=["Agent and service share the same normalized base endpoint."],
                )

        python_targets = [
            item for item in agents if item.item_type == "python_target"
        ]
        http_agents = [
            item for item in agents if item.item_type == "agent" and item.endpoint
        ]
        for target in python_targets:
            matches = [
                agent
                for agent in http_agents
                if target.name == agent.name
                or target.name in agent.metadata.get("target_names", [])
            ]
            if len(matches) == 1:
                self._record(
                    correlations,
                    by_id,
                    [target.stable_id, matches[0].stable_id],
                    logical_name=target.name,
                    confidence=DiscoveryConfidence.HIGH,
                    reasons=["Enrolled target name matches project HTTP agent metadata."],
                )

        for endpoint in ollama:
            matches = [
                service
                for service in services
                if normalize_identity_url(service.endpoint or "")
                == normalize_identity_url(endpoint.endpoint or "")
            ]
            if len(matches) == 1:
                self._record(
                    correlations,
                    by_id,
                    [endpoint.stable_id, matches[0].stable_id],
                    logical_name="Ollama",
                    confidence=DiscoveryConfidence.CONFIRMED,
                    reasons=["Ollama API and HTTP service share the same normalized endpoint."],
                )

        for container in containers:
            host_ports = {
                mapping.get("host_port")
                for mapping in container.port_mappings
                if mapping.get("host_port")
            }
            for port in host_ports:
                matches = listeners_by_port.get(port, [])
                if len(matches) == 1:
                    self._record(
                        correlations,
                        by_id,
                        [container.stable_id, matches[0].stable_id],
                        logical_name=container.name,
                        confidence=DiscoveryConfidence.MEDIUM,
                        reasons=["Docker-reported host port matches one host listener."],
                    )

        return sorted(items, key=_sort_key), sorted(
            correlations, key=lambda row: row.correlation_id
        )

    @staticmethod
    def _record(
        records: list[CorrelationRecord],
        by_id: dict[str, InventoryItem],
        item_ids: list[str],
        *,
        logical_name: str,
        confidence: DiscoveryConfidence,
        reasons: list[str],
    ) -> None:
        unique = sorted(set(item_ids))
        if len(unique) < 2:
            return
        correlation_id = stable_id("correlation", *unique)
        if any(record.correlation_id == correlation_id for record in records):
            return
        records.append(
            CorrelationRecord(
                correlation_id=correlation_id,
                logical_name=logical_name,
                item_ids=unique,
                confidence=confidence,
                reasons=reasons,
            )
        )
        for item_id in unique:
            item = by_id[item_id]
            item.related_ids = sorted(
                set(item.related_ids + [other for other in unique if other != item_id])
            )


def _sort_key(item: InventoryItem) -> tuple[str, str, str]:
    item_type = (
        item.item_type.value
        if hasattr(item.item_type, "value")
        else str(item.item_type)
    )
    return item_type, item.name.lower(), item.stable_id

