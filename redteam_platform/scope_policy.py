"""Central target normalization, authorization, and scope enforcement."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urljoin, urlparse, urlunparse

from redteam_platform.schemas import (
    AssessmentProfile,
    AuthorizationDecision,
    AuthorizationRequest,
    AuthorizationRecord,
    ScopeClassification,
)
from redteam_platform.settings import Settings


METADATA_ADDRESSES = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("100.100.100.200"),
    ipaddress.ip_address("fd00:ec2::254"),
}
GLOBAL_BROADCAST = ipaddress.ip_address("255.255.255.255")


class ScopeDeniedError(PermissionError):
    """Raised before any active tool receives a denied target."""


class ScopePolicy:
    def __init__(
        self,
        settings: Settings,
        resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
    ):
        self.settings = settings
        self.resolver = resolver
        configured = [ipaddress.ip_network(value, strict=False) for value in settings.allowed_cidrs]
        self.allowed_networks = list(
            dict.fromkeys(
                [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"), *configured]
            )
        )

    @staticmethod
    def normalize_hostname(hostname: str) -> str:
        host = str(hostname or "").strip().rstrip(".").lower()
        if not host:
            raise ScopeDeniedError("Target hostname is empty.")
        if any(char.isspace() for char in host):
            raise ScopeDeniedError("Target hostname contains whitespace.")
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ScopeDeniedError("Target hostname is not valid IDNA.") from exc

    @staticmethod
    def _parse_target(target: str) -> tuple[str, str, int | None, str]:
        raw = str(target or "").strip()
        if not raw:
            raise ScopeDeniedError("Target is required.")
        if "://" not in raw:
            try:
                address = ipaddress.ip_address(raw)
            except ValueError:
                pass
            else:
                raw = f"host://[{address}]" if address.version == 6 else f"host://{address}"
        parsed = urlparse(raw if "://" in raw else f"host://{raw}")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeDeniedError("Credential-bearing URLs are not permitted.")
        if parsed.scheme not in {"http", "https", "host", "ssh", "python"}:
            raise ScopeDeniedError(f"Unsupported target scheme: {parsed.scheme}.")
        if not parsed.hostname:
            raise ScopeDeniedError("Target must include a hostname or IP address.")
        hostname = ScopePolicy.normalize_hostname(parsed.hostname)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ScopeDeniedError("Target port is invalid.") from exc
        if parsed.scheme in {"http", "https"}:
            normalized = urlunparse(
                (
                    parsed.scheme,
                    f"[{hostname}]" if ":" in hostname else hostname,
                    parsed.path or "/",
                    "",
                    "",
                    "",
                )
            )
            if port:
                netloc = f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
                normalized = urlunparse(
                    (parsed.scheme, netloc, parsed.path or "/", "", "", "")
                )
        else:
            normalized_host = f"[{hostname}]" if ":" in hostname else hostname
            normalized = f"{parsed.scheme}://{normalized_host}" + (f":{port}" if port else "")
        return parsed.scheme, hostname, port, normalized

    def _resolve(self, hostname: str, port: int | None) -> list[ipaddress._BaseAddress]:
        try:
            return [ipaddress.ip_address(hostname)]
        except ValueError:
            pass
        try:
            answers = self.resolver(hostname, port or 0, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ScopeDeniedError(f"DNS resolution failed for {hostname}: {exc}") from exc
        addresses: list[ipaddress._BaseAddress] = []
        for answer in answers:
            address = ipaddress.ip_address(answer[4][0].split("%", 1)[0])
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise ScopeDeniedError(f"DNS returned no addresses for {hostname}.")
        return addresses

    def _blocked_reason(self, address: ipaddress._BaseAddress) -> str | None:
        if address in METADATA_ADDRESSES:
            return "cloud metadata destination"
        if address == GLOBAL_BROADCAST:
            return "global broadcast destination"
        if address.is_unspecified:
            return "unspecified destination"
        if address.is_multicast:
            return "multicast destination"
        if address.is_link_local:
            return "link-local destination"
        for network in self.allowed_networks:
            if address == network.broadcast_address and network.num_addresses > 2:
                return "configured-network broadcast destination"
        return None

    def _domain_allowed(self, hostname: str) -> bool:
        for allowed in self.settings.allowed_domains:
            normalized = self.normalize_hostname(allowed.lstrip("."))
            if hostname == normalized or hostname.endswith("." + normalized):
                return True
        return False

    @staticmethod
    def _decision(
        *,
        allowed: bool,
        normalized_target: str,
        classification: ScopeClassification,
        rule: str,
        addresses: list[ipaddress._BaseAddress] | None = None,
        reasons: list[str] | None = None,
        evidence: dict | None = None,
    ) -> AuthorizationDecision:
        reason_list = reasons or ["Target is within configured scope."]
        resolved = [str(address) for address in (addresses or [])]
        return AuthorizationDecision(
            allowed=allowed,
            normalized_target=normalized_target,
            classification=classification,
            resolved_addresses=resolved,
            reasons=reason_list,
            reason="; ".join(reason_list),
            policy_rule=rule,
            evidence={"resolved_addresses": resolved, **(evidence or {})},
        )

    def decide(
        self,
        target: str,
        *,
        active: bool,
        public_mode: bool = False,
        interactive_confirmation: bool = False,
        authorization_statement: str | None = None,
    ) -> AuthorizationDecision:
        scheme, hostname, port, normalized = self._parse_target(target)

        if scheme == "python":
            addresses = []
            classification = ScopeClassification.LOOPBACK
        elif scheme == "ssh":
            allowed_aliases = {
                self.normalize_hostname(alias) for alias in self.settings.allowed_kali_aliases
            }
            if hostname not in allowed_aliases:
                return self._decision(
                    allowed=False,
                    normalized_target=normalized,
                    classification=ScopeClassification.BLOCKED,
                    rule="deny-unconfigured-kali-alias",
                    reasons=["Kali SSH alias is not explicitly configured."],
                    evidence={"hostname": hostname, "active": active},
                )
            addresses = []
            classification = ScopeClassification.LAB
        else:
            addresses = self._resolve(hostname, port)
            blocked = [reason for address in addresses if (reason := self._blocked_reason(address))]
            if blocked:
                return self._decision(
                    allowed=False,
                    normalized_target=normalized,
                    classification=ScopeClassification.BLOCKED,
                    addresses=addresses,
                    reasons=sorted(set(blocked)),
                    rule="deny-special-address",
                    evidence={"hostname": hostname, "active": active},
                )
            if all(address.is_loopback for address in addresses):
                classification = ScopeClassification.LOOPBACK
            elif all(any(address in network for network in self.allowed_networks) for address in addresses):
                classification = ScopeClassification.LAB
            elif any(address.is_private for address in addresses):
                classification = ScopeClassification.PRIVATE_DENIED
            else:
                classification = ScopeClassification.PUBLIC

        reasons: list[str] = []
        allowed = classification in {ScopeClassification.LOOPBACK, ScopeClassification.LAB}
        if classification == ScopeClassification.PRIVATE_DENIED:
            reasons.append("Private destination is not in configured allowed CIDRs.")
        if classification == ScopeClassification.PUBLIC:
            if not self.settings.allow_public:
                reasons.append("Public targets are disabled by configuration.")
            if not public_mode:
                reasons.append("Public mode was not deliberately enabled.")
            if not self._domain_allowed(hostname):
                reasons.append("Public hostname is not on the configured allowlist.")
            if not interactive_confirmation:
                reasons.append("Public targets require interactive confirmation.")
            allowed = not reasons
        if active:
            statement = str(authorization_statement or "").strip()
            if len(statement) < 12:
                allowed = False
                reasons.append("Active testing requires a human authorization statement.")
        if classification == ScopeClassification.LOOPBACK:
            rule = "allow-loopback"
        elif classification == ScopeClassification.LAB:
            rule = "allow-configured-lab"
        elif classification == ScopeClassification.PUBLIC and allowed:
            rule = "allow-explicit-public"
        elif classification == ScopeClassification.PUBLIC:
            rule = "deny-public-default"
        elif classification == ScopeClassification.PRIVATE_DENIED:
            rule = "deny-unconfigured-private"
        else:
            rule = "default-deny"
        if active and len(str(authorization_statement or "").strip()) < 12:
            rule = "deny-missing-human-authorization"
        return self._decision(
            allowed=allowed,
            normalized_target=normalized,
            classification=classification,
            addresses=addresses,
            reasons=reasons or ["Target is within configured scope."],
            rule=rule,
            evidence={"hostname": hostname, "scheme": scheme, "port": port, "active": active},
        )

    def authorize_request(self, request: AuthorizationRequest) -> AuthorizationRecord:
        return self.authorize(
            request.target,
            statement=request.human_authorization_statement,
            source=request.source,
            profile=request.requested_profile,
            public_mode=request.public_mode,
            interactive_confirmation=request.confirmed_interactively,
        )

    def authorize(
        self,
        target: str,
        *,
        statement: str,
        source: str,
        profile: AssessmentProfile,
        public_mode: bool = False,
        interactive_confirmation: bool = False,
    ) -> AuthorizationRecord:
        if source not in {"human-cli", "human-api", "human-config"}:
            raise ScopeDeniedError("Authorization source must be human-controlled.")
        decision = self.decide(
            target,
            active=True,
            public_mode=public_mode,
            interactive_confirmation=interactive_confirmation,
            authorization_statement=statement,
        )
        if not decision.allowed:
            raise ScopeDeniedError("; ".join(decision.reasons))
        return AuthorizationRecord(
            decision=decision,
            statement=statement.strip(),
            target=target,
            normalized_target=decision.normalized_target,
            requested_profile=profile,
            scope_classification=decision.classification,
            human_authorization_statement=statement.strip(),
            policy_decision=decision,
            source=source,
            profile=profile,
            public_mode=public_mode,
            confirmed_interactively=interactive_confirmation,
        )

    def require_record(self, target: str, record: AuthorizationRecord) -> AuthorizationDecision:
        if record.source not in {"human-cli", "human-api", "human-config"}:
            raise ScopeDeniedError("Model-generated authorization is never accepted.")
        current = self.decide(
            target,
            active=True,
            public_mode=record.public_mode,
            interactive_confirmation=record.confirmed_interactively,
            authorization_statement=record.statement,
        )
        if not current.allowed:
            raise ScopeDeniedError("; ".join(current.reasons))
        if current.normalized_target != record.decision.normalized_target:
            raise ScopeDeniedError("Authorization target does not match the requested target.")
        if set(current.resolved_addresses) != set(record.decision.resolved_addresses):
            raise ScopeDeniedError("Target resolution changed after authorization.")
        return current

    def validate_redirect(
        self,
        original_target: str,
        location: str,
        record: AuthorizationRecord,
    ) -> AuthorizationDecision:
        redirected = urljoin(record.decision.normalized_target, location)
        original = self._parse_target(original_target)[1]
        redirected_host = self._parse_target(redirected)[1]
        if original != redirected_host and not self._domain_allowed(redirected_host):
            raise ScopeDeniedError("Cross-host redirect is not explicitly allowed.")
        decision = self.decide(
            redirected,
            active=True,
            public_mode=record.public_mode,
            interactive_confirmation=record.confirmed_interactively,
            authorization_statement=record.statement,
        )
        if not decision.allowed:
            raise ScopeDeniedError("; ".join(decision.reasons))
        if set(decision.resolved_addresses) != set(record.decision.resolved_addresses):
            raise ScopeDeniedError("Redirect resolution differs from the authorized destination.")
        return decision


def require_authorized_target(
    target: str,
    record: AuthorizationRecord,
    settings: Settings,
) -> AuthorizationDecision:
    return ScopePolicy(settings).require_record(target, record)
