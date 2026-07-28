"""Typed adaptive probe registry backed by Phase 5 probe definitions."""

from __future__ import annotations

from pydantic import Field

from redteam_platform.assessments.models import ProbeDefinition, StepMode
from redteam_platform.assessments.probes.packs import AI_PROMPTS
from redteam_platform.schemas import VersionedModel
from redteam_platform.targets.models import TargetKind


AI_TARGET_KINDS = [
    TargetKind.PYTHON_AGENT,
    TargetKind.HTTP_AGENT,
    TargetKind.OPENAI_COMPATIBLE,
    TargetKind.OLLAMA_ENDPOINT,
    TargetKind.OLLAMA_AGENT,
    TargetKind.DEXTER,
]


class AdaptiveProbeTemplate(VersionedModel):
    template_id: str
    version: str = "1.0"
    category: str
    name: str
    base_prompt: str
    evaluation_rule: str
    target_kinds: list[TargetKind]
    allowed_profiles: list[str] = Field(default_factory=lambda: ["standard", "deep-lab"])
    allowed_modes: list[str] = Field(
        default_factory=lambda: ["guided", "adaptive", "comparative"]
    )
    allowed_mutations: list[str] = Field(
        default_factory=lambda: [
            "paraphrase",
            "role",
            "ordering",
            "benign_encoding",
            "synthetic_history",
            "synthetic_canary",
            "language",
        ]
    )
    required_capability: str = "invoke"
    required_tool: str = "python"
    operation: str = "invoke"
    request_count: int = Field(default=1, ge=1, le=3)
    prompt_max_characters: int = Field(default=4000, ge=64, le=20000)
    evaluator: str
    detector: str
    canary_supported: bool = False
    standards_mappings: list[str] = Field(
        default_factory=lambda: ["OWASP-LLM01", "MITRE-ATLAS"]
    )

    def phase5_probe(
        self,
        *,
        prompt: str,
        target_kind: TargetKind,
        canary: str | None = None,
        probe_id: str | None = None,
    ) -> ProbeDefinition:
        tool = "python" if target_kind == TargetKind.PYTHON_AGENT else "http"
        return ProbeDefinition(
            probe_id=probe_id or self.template_id,
            version=self.version,
            category=self.category,
            name=self.name,
            target_kinds=[target_kind],
            mode=StepMode.ACTIVE,
            request_count=self.request_count,
            timeout_seconds=10,
            required_tool=tool,
            expected_evidence=f"{tool} result",
            evaluation_rule=self.evaluation_rule,
            safety_constraints=[
                "single authorized target",
                "bounded response",
                "no destructive action",
                "no credential guessing",
                "registered adaptive mutation only",
            ],
            operation="invoke",
            parameters={"prompt": prompt},
            synthetic_canary=canary,
        )


class AdaptiveTemplateRegistry:
    def __init__(self):
        self._templates: dict[str, AdaptiveProbeTemplate] = {}
        for probe_id, category, name, prompt, rule in AI_PROMPTS:
            self.register(
                AdaptiveProbeTemplate(
                    template_id=probe_id,
                    category=category,
                    name=name,
                    base_prompt=prompt,
                    evaluation_rule=rule,
                    target_kinds=AI_TARGET_KINDS,
                    evaluator="phase5-deterministic",
                    detector=rule,
                    canary_supported="{CANARY}" in prompt,
                )
            )

    def register(self, template: AdaptiveProbeTemplate) -> None:
        if template.template_id in self._templates:
            raise ValueError(f"Duplicate adaptive template {template.template_id}.")
        self._templates[template.template_id] = template

    def get(self, template_id: str) -> AdaptiveProbeTemplate | None:
        return self._templates.get(template_id)

    def require(self, template_id: str) -> AdaptiveProbeTemplate:
        template = self.get(template_id)
        if template is None:
            raise KeyError(f"Unknown registered adaptive template: {template_id}")
        return template

    def list(
        self,
        *,
        target_kind: TargetKind | str | None = None,
        categories: list[str] | None = None,
    ) -> list[AdaptiveProbeTemplate]:
        kind = TargetKind(target_kind) if target_kind is not None else None
        selected = set(categories or [])
        return [
            template
            for template in self._templates.values()
            if (kind is None or kind in template.target_kinds)
            and (not selected or template.category in selected)
        ]


DEFAULT_TEMPLATE_REGISTRY = AdaptiveTemplateRegistry()
