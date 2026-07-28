import socket
import unittest
from unittest.mock import Mock, patch

from pydantic import ValidationError

from redteam_platform.adapters import AdapterError, HTTPAgentAdapter
from redteam_platform.schemas import AssessmentProfile, AuthorizationRequest
from redteam_platform.scope_policy import ScopeDeniedError, ScopePolicy
from redteam_platform.settings import Settings


def resolver(*addresses):
    def resolve(host, port, type=socket.SOCK_STREAM):
        rows = []
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            rows.append((family, type, 6, "", (address, port)))
        return rows

    return resolve


def failing_resolver(host, port, type=socket.SOCK_STREAM):
    raise socket.gaierror("synthetic resolution failure")


AUTHORIZATION = "I own this isolated test target and authorize bounded active assessment."


class ScopePolicyTests(unittest.TestCase):
    def test_ipv4_and_ipv6_loopback_are_allowed(self):
        settings = Settings()
        ipv4 = ScopePolicy(settings, resolver("127.0.0.1")).decide(
            "http://localhost:8000/path?secret=value", active=False
        )
        ipv6 = ScopePolicy(settings).decide("::1", active=False)
        self.assertTrue(ipv4.allowed)
        self.assertEqual(ipv4.normalized_target, "http://localhost:8000/path")
        self.assertEqual(ipv4.policy_rule, "allow-loopback")
        self.assertTrue(ipv6.allowed)
        self.assertEqual(ipv6.normalized_target, "host://[::1]")

    def test_configured_private_lab_cidr_is_allowed(self):
        policy = ScopePolicy(
            Settings(allowed_cidrs=["10.42.0.0/16"]), resolver("10.42.2.5")
        )
        decision = policy.decide("http://lab.internal:9000", active=False)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.classification, "lab")
        self.assertEqual(decision.policy_rule, "allow-configured-lab")

    def test_public_ip_is_denied_by_default(self):
        decision = ScopePolicy(Settings()).decide("https://8.8.8.8", active=False)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.policy_rule, "deny-public-default")

    def test_special_destinations_are_denied(self):
        cases = {
            "http://169.254.1.1": "link-local",
            "http://224.0.0.1": "multicast",
            "http://0.0.0.0": "unspecified",
            "http://255.255.255.255": "global broadcast",
            "http://169.254.169.254": "cloud metadata",
            "http://100.100.100.200": "cloud metadata",
            "http://[fd00:ec2::254]": "cloud metadata",
        }
        for target, expected in cases.items():
            with self.subTest(target=target):
                decision = ScopePolicy(Settings()).decide(target, active=False)
                self.assertFalse(decision.allowed)
                self.assertIn(expected, decision.reason)
                self.assertEqual(decision.policy_rule, "deny-special-address")

    def test_credentials_and_invalid_schemes_are_rejected(self):
        policy = ScopePolicy(Settings())
        with self.assertRaisesRegex(ScopeDeniedError, "Credential-bearing"):
            policy.decide("http://user:password@127.0.0.1", active=False)
        with self.assertRaisesRegex(ScopeDeniedError, "Unsupported target scheme"):
            policy.decide("file:///etc/passwd", active=False)

    def test_every_dns_answer_must_be_in_scope(self):
        policy = ScopePolicy(Settings(), resolver("127.0.0.1", "10.1.2.3"))
        decision = policy.decide("http://mixed.test", active=False)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.classification, "private_denied")
        self.assertEqual(set(decision.resolved_addresses), {"127.0.0.1", "10.1.2.3"})

    def test_dns_failure_fails_closed(self):
        with self.assertRaisesRegex(ScopeDeniedError, "DNS resolution failed"):
            ScopePolicy(Settings(), failing_resolver).decide("http://unresolved.test", active=False)

    def test_allowed_domain_requires_all_public_controls_and_supports_suffix(self):
        settings = Settings(allow_public=True, allowed_domains=["example.com"])
        policy = ScopePolicy(settings, resolver("93.184.216.34"))
        denied = policy.decide(
            "https://api.example.com",
            active=True,
            public_mode=True,
            interactive_confirmation=False,
            authorization_statement=AUTHORIZATION,
        )
        self.assertFalse(denied.allowed)
        allowed = policy.decide(
            "https://api.example.com",
            active=True,
            public_mode=True,
            interactive_confirmation=True,
            authorization_statement=AUTHORIZATION,
        )
        self.assertTrue(allowed.allowed)
        lookalike = policy.decide(
            "https://notexample.com",
            active=True,
            public_mode=True,
            interactive_confirmation=True,
            authorization_statement=AUTHORIZATION,
        )
        self.assertFalse(lookalike.allowed)

    def test_human_statement_is_required_and_model_source_is_impossible(self):
        policy = ScopePolicy(Settings())
        with self.assertRaises(ScopeDeniedError):
            policy.authorize(
                "python://fixture",
                statement="short",
                source="human-cli",
                profile=AssessmentProfile.STANDARD,
            )
        with self.assertRaises(ScopeDeniedError):
            policy.authorize(
                "python://fixture",
                statement=AUTHORIZATION,
                source="model",
                profile=AssessmentProfile.STANDARD,
            )
        with self.assertRaises(ValidationError):
            AuthorizationRequest(
                target="python://fixture",
                requested_profile=AssessmentProfile.STANDARD,
                human_authorization_statement=AUTHORIZATION,
                source="model",
            )

    def test_dns_rebinding_invalidates_authorization(self):
        settings = Settings(allowed_cidrs=["10.10.0.0/16"])
        policy = ScopePolicy(settings, resolver("127.0.0.1"))
        record = policy.authorize(
            "http://lab.example:8000",
            statement=AUTHORIZATION,
            source="human-cli",
            profile=AssessmentProfile.STANDARD,
        )
        policy.resolver = resolver("10.10.1.2")
        with self.assertRaisesRegex(ScopeDeniedError, "resolution changed"):
            policy.require_record("http://lab.example:8000", record)

    def test_denied_http_target_never_opens_client(self):
        adapter = HTTPAgentAdapter(Settings())
        with patch("redteam_platform.adapters.httpx.Client") as client:
            with self.assertRaises(AdapterError):
                adapter.identify("https://8.8.8.8")
        client.assert_not_called()

    def test_denied_kali_url_never_reaches_tunnel_ssh_or_kali(self):
        from kali_url_attack import run_kali_url_attack

        with patch("kali_url_attack._start_reverse_tunnel") as tunnel, patch(
            "kali_url_attack._run_remote"
        ) as ssh, patch("kali_url_attack._web_recon") as kali:
            with self.assertRaises(ScopeDeniedError):
                run_kali_url_attack(
                    host="kali-redteam",
                    url="https://8.8.8.8",
                    tunnel_local=True,
                    authorization_statement=AUTHORIZATION,
                    policy_settings=Settings(allowed_kali_aliases=["kali-redteam"]),
                )
        tunnel.assert_not_called()
        ssh.assert_not_called()
        kali.assert_not_called()

    def test_denied_kali_alias_never_reaches_subprocess_or_server(self):
        from kali_agent_attack import run_kali_agent_attack

        with patch("kali_agent_attack._start_agent_server") as server, patch(
            "kali_agent_attack._start_reverse_tunnel"
        ) as tunnel, patch("kali_agent_attack.subprocess.run") as subprocess_run:
            with self.assertRaises(ScopeDeniedError):
                run_kali_agent_attack(
                    host="not-allowed",
                    authorization_statement=AUTHORIZATION,
                    policy_settings=Settings(allowed_kali_aliases=[]),
                )
        server.assert_not_called()
        tunnel.assert_not_called()
        subprocess_run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
