"""Safe textual mutation helpers; no mutation is executable."""

from __future__ import annotations

import hashlib
import re
from difflib import SequenceMatcher

from redteam_platform.adaptive_engine.models import ProbeMutation


URL_RE = re.compile(r"(?i)\b(?:https?|file|ftp)://[^\s]+")
SHELL_RE = re.compile(
    r"(?i)(?:^|[\s;|&])(?:sudo|sh|bash|zsh|powershell|cmd|curl|wget|nc|ncat|ssh|scp|rm|chmod|chown)\b"
)
SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|password|access[_-]?token|private[_-]?key|bearer)\b\s*[:=]?\s*\S+"
)
PATH_RE = re.compile(r"(?:^|\s)(?:/Users/|/etc/|/var/|/private/|~/|\.\./)")
DESTRUCTIVE_RE = re.compile(
    r"(?i)\b(?:delete|destroy|wipe|exfiltrate|disable security|drop database|format disk)\b"
)


def normalize_prompt(value: str) -> str:
    return " ".join(re.sub(r"[^\w\s{}-]", " ", value.lower()).split())


def prompt_hash(value: str) -> str:
    return hashlib.sha256(normalize_prompt(value).encode()).hexdigest()


def word_similarity(left: str, right: str) -> float:
    left_words = set(normalize_prompt(left).split())
    right_words = set(normalize_prompt(right).split())
    jaccard = len(left_words & right_words) / max(1, len(left_words | right_words))
    sequence = SequenceMatcher(None, normalize_prompt(left), normalize_prompt(right)).ratio()
    return round(max(jaccard, sequence), 4)


def unsafe_mutation_reason(base_prompt: str, candidate: str) -> str | None:
    for label, pattern in (
        ("new URL", URL_RE),
        ("shell command", SHELL_RE),
        ("credential or secret", SECRET_RE),
        ("local path", PATH_RE),
        ("destructive or exfiltration request", DESTRUCTIVE_RE),
    ):
        base_matches = set(pattern.findall(base_prompt))
        candidate_matches = set(pattern.findall(candidate))
        if candidate_matches - base_matches:
            return f"Mutation introduced a prohibited {label}."
    return None


def build_mutation(
    *,
    template_id: str,
    category: str,
    original_prompt: str,
    mutated_prompt: str,
    mutation_types: list[str] | None = None,
    lineage: list[str] | None = None,
) -> ProbeMutation:
    digest = prompt_hash(mutated_prompt)
    return ProbeMutation(
        mutation_id=f"mutation_{digest[:16]}",
        template_id=template_id,
        category=category,
        original_prompt=original_prompt,
        mutated_prompt=mutated_prompt,
        mutation_types=mutation_types or [],
        lineage=lineage or [template_id],
        normalized_prompt_hash=digest,
    )
