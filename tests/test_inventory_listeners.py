import socket
import unittest
from types import SimpleNamespace

from redteam_platform.inventory.listeners import (
    ListenerDiscovery,
    redact_command_arguments,
)
from redteam_platform.inventory.models import DiscoverySource
from redteam_platform.settings import Settings


class FakeAccessDenied(Exception):
    pass


class FakeNoSuchProcess(Exception):
    pass


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid

    def name(self):
        return "python"

    def exe(self):
        return "/usr/bin/python3"

    def username(self):
        return "tester"

    def cmdline(self):
        return [
            "python",
            "server.py",
            "--token=secret-value",
            "http://user:pass@localhost:8000/path?key=value",
        ]


class FakePsutil:
    AccessDenied = FakeAccessDenied
    NoSuchProcess = FakeNoSuchProcess
    CONN_LISTEN = "LISTEN"

    def __init__(self, connections, process_error=False):
        self.connections = connections
        self.process_error = process_error

    def net_connections(self, kind):
        return self.connections

    def Process(self, pid):
        if self.process_error:
            raise FakeAccessDenied()
        return FakeProcess(pid)


def conn(address, port, *, transport="tcp", family=socket.AF_INET, pid=10):
    return SimpleNamespace(
        type=socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM,
        status="" if transport == "udp" else "LISTEN",
        laddr=SimpleNamespace(ip=address, port=port),
        raddr=(),
        family=family,
        pid=pid,
    )


class ListenerInventoryTests(unittest.TestCase):
    def test_psutil_collects_ipv4_ipv6_tcp_udp_and_redacts_process_command(self):
        settings = Settings(_env_file=None, include_udp=True)
        fake = FakePsutil(
            [
                conn("127.0.0.1", 8000),
                conn("::1", 8001, family=socket.AF_INET6),
                conn("0.0.0.0", 5353, transport="udp"),
                conn("10.0.0.5", 9000),
            ]
        )
        items, errors = ListenerDiscovery(
            settings, psutil_module=fake, system="darwin"
        ).collect()
        self.assertEqual(errors, [])
        self.assertEqual(len(items), 4)
        self.assertTrue(next(item for item in items if item.port == 8000).loopback_only)
        self.assertEqual(
            next(item for item in items if item.port == 8001).address_family,
            "ipv6",
        )
        self.assertEqual(next(item for item in items if item.port == 5353).protocol, "udp")
        self.assertTrue(next(item for item in items if item.port == 5353).wildcard_bound)
        self.assertEqual(
            next(item for item in items if item.port == 9000).reachability,
            "private_interface",
        )
        serialized = items[0].model_dump_json()
        self.assertNotIn("secret-value", serialized)
        self.assertNotIn("user:pass", serialized)

    def test_linux_psutil_uses_same_passive_listener_table(self):
        fake = FakePsutil([conn("127.0.0.1", 8080)])
        items, errors = ListenerDiscovery(
            Settings(_env_file=None),
            psutil_module=fake,
            system="linux",
        ).collect()
        self.assertEqual(errors, [])
        self.assertEqual(items[0].discovery_source, DiscoverySource.PSUTIL)

    def test_process_access_denied_does_not_drop_listener(self):
        fake = FakePsutil([conn("127.0.0.1", 8080)], process_error=True)
        items, errors = ListenerDiscovery(
            Settings(_env_file=None), psutil_module=fake
        ).collect()
        self.assertEqual(len(items), 1)
        self.assertTrue(items[0].process.access_denied)
        self.assertEqual(errors[0].code, "process_access_denied")

    def test_lsof_fallback_parses_tcp_udp_ipv4_ipv6_and_ignores_connections(self):
        discovery = ListenerDiscovery(
            Settings(_env_file=None, include_udp=True), system="darwin"
        )
        output = """COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
Python 123 test 4u IPv4 0 0 TCP 127.0.0.1:8000 (LISTEN)
Python 123 test 5u IPv6 0 0 TCP [::1]:8001 (LISTEN)
mdns 44 root 6u IPv4 0 0 UDP *:5353
curl 55 test 7u IPv4 0 0 TCP 127.0.0.1:50000->1.1.1.1:443 (ESTABLISHED)
"""
        items = discovery.parse_lsof(output)
        self.assertEqual({item.port for item in items}, {8000, 8001, 5353})
        self.assertTrue(next(item for item in items if item.port == 5353).wildcard_bound)

    def test_ss_fallback_parses_tcp_udp_and_process(self):
        discovery = ListenerDiscovery(
            Settings(_env_file=None, include_udp=True), system="linux"
        )
        output = """tcp LISTEN 0 128 127.0.0.1:8000 0.0.0.0:* users:((\"python\",pid=123,fd=3))
udp UNCONN 0 0 [::]:5353 [::]:* users:((\"mdns\",pid=44,fd=4))
"""
        items = discovery.parse_ss(output)
        self.assertEqual({item.port for item in items}, {8000, 5353})
        self.assertEqual(next(item for item in items if item.port == 8000).process_name, "python")
        self.assertTrue(next(item for item in items if item.port == 5353).wildcard_bound)

    def test_unsupported_platform_reports_typed_error(self):
        items, errors = ListenerDiscovery(
            Settings(_env_file=None, listener_discovery_method="native"),
            system="windows",
        ).collect()
        self.assertEqual(items, [])
        self.assertEqual(errors[0].code, "unsupported_platform")

    def test_command_redaction_handles_split_and_inline_secrets(self):
        text = redact_command_arguments(
            [
                "service",
                "--password",
                "plain-secret",
                "--api-key=value",
                "Bearer secret-token",
            ]
        )
        self.assertNotIn("plain-secret", text)
        self.assertNotIn("value", text)
        self.assertNotIn("secret-token", text)
        self.assertGreaterEqual(text.count("<REDACTED>"), 3)


if __name__ == "__main__":
    unittest.main()
