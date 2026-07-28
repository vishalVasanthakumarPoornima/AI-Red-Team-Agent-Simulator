import json
import subprocess
import unittest
from types import SimpleNamespace

from redteam_platform.inventory.docker import DockerDiscovery
from redteam_platform.inventory.kali import KALI_TOOLS, KaliDiscovery
from redteam_platform.inventory.models import (
    DockerContainer,
    InventoryStatus,
    ToolState,
)
from redteam_platform.settings import Settings


class DockerInventoryTests(unittest.TestCase):
    def test_docker_absent(self):
        items, errors = DockerDiscovery(
            Settings(_env_file=None), which=lambda name: None
        ).collect()
        self.assertEqual(items, [])
        self.assertEqual(errors[0].code, "docker_unavailable")

    def test_daemon_unavailable_and_permission_denied(self):
        for stderr, code in (
            ("Cannot connect to the Docker daemon", "docker_daemon_unavailable"),
            ("permission denied", "docker_permission_denied"),
        ):
            with self.subTest(code=code):
                runner = lambda *args, **kwargs: SimpleNamespace(
                    returncode=1, stdout="", stderr=stderr
                )
                _, errors = DockerDiscovery(
                    Settings(_env_file=None),
                    which=lambda name: "/usr/bin/docker",
                    runner=runner,
                ).collect()
                self.assertEqual(errors[0].code, code)

    def test_no_containers_is_success(self):
        runner = lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout="", stderr=""
        )
        items, errors = DockerDiscovery(
            Settings(_env_file=None),
            which=lambda name: "/usr/bin/docker",
            runner=runner,
        ).collect()
        self.assertEqual(items, [])
        self.assertEqual(errors, [])

    def test_running_container_and_port_mapping_without_mutation(self):
        calls = []
        row = {
            "ID": "abc123",
            "Names": "agent-service",
            "Image": "fixture:latest",
            "State": "running",
            "Status": "Up 10 minutes (healthy)",
            "Ports": "127.0.0.1:18101->8000/tcp",
            "Networks": "bridge",
            "Labels": "com.docker.compose.project=redteam,secret.token=hidden",
        }

        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(
                returncode=0, stdout=json.dumps(row) + "\n", stderr=""
            )

        items, errors = DockerDiscovery(
            Settings(_env_file=None),
            which=lambda name: "/usr/bin/docker",
            runner=runner,
        ).collect()
        self.assertEqual(errors, [])
        self.assertIsInstance(items[0], DockerContainer)
        self.assertEqual(items[0].status, InventoryStatus.RUNNING)
        self.assertEqual(items[0].port_mappings[0]["host_port"], 18101)
        self.assertNotIn("secret.token", items[0].labels)
        self.assertEqual(calls[0][:2], ["docker", "ps"])
        self.assertFalse(
            any(action in calls[0] for action in ("start", "stop", "exec", "pull", "inspect"))
        )

    def test_stopped_containers_are_only_requested_when_configured(self):
        calls = []
        row = {
            "ID": "stopped123",
            "Names": "configured-agent",
            "Image": "fixture:latest",
            "State": "exited",
            "Status": "Exited (0) 2 hours ago",
            "Ports": "",
            "Networks": "bridge",
            "Labels": "service=agent",
        }

        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(row) + "\n",
                stderr="",
            )

        items, errors = DockerDiscovery(
            Settings(_env_file=None, include_stopped_containers=True),
            which=lambda name: "/usr/bin/docker",
            runner=runner,
        ).collect()
        self.assertEqual(errors, [])
        self.assertEqual(items[0].status, InventoryStatus.STOPPED)
        self.assertIn("--all", calls[0])
        self.assertFalse(
            any(action in calls[0] for action in ("start", "stop", "exec", "pull", "inspect"))
        )


class KaliInventoryTests(unittest.TestCase):
    def test_not_configured_is_not_error(self):
        items, errors = KaliDiscovery(Settings(_env_file=None)).collect()
        self.assertEqual(errors, [])
        self.assertEqual(items[0].status, InventoryStatus.NOT_CONFIGURED)

    def configured(self, **updates):
        return Settings(
            _env_file=None,
            kali_ssh_host="kali-lab",
            allowed_kali_aliases=["kali-lab"],
            **updates,
        )

    def test_ssh_binary_missing(self):
        items, errors = KaliDiscovery(
            self.configured(), which=lambda name: None
        ).collect()
        self.assertEqual(items[0].ssh_state, ToolState.MISSING)
        self.assertEqual(errors[0].code, "ssh_missing")

    def test_configured_alias_allowed_without_live_connection(self):
        runner_called = False

        def runner(*args, **kwargs):
            nonlocal runner_called
            runner_called = True

        items, errors = KaliDiscovery(
            self.configured(),
            which=lambda name: "/usr/bin/ssh",
            runner=runner,
        ).collect(live=False)
        self.assertEqual(errors, [])
        self.assertFalse(runner_called)
        self.assertFalse(items[0].live_check_performed)
        self.assertEqual(items[0].ssh_state, ToolState.AVAILABLE)

    def test_disallowed_alias_never_runs_ssh(self):
        calls = []
        settings = Settings(
            _env_file=None,
            kali_ssh_host="kali-not-allowed",
            allowed_kali_aliases=[],
        )
        items, errors = KaliDiscovery(
            settings,
            which=lambda name: "/usr/bin/ssh",
            runner=lambda *args, **kwargs: calls.append(args),
        ).collect(live=True)
        self.assertEqual(calls, [])
        self.assertEqual(errors[0].code, "kali_scope_denied")
        self.assertEqual(items[0].status, InventoryStatus.UNAVAILABLE)

    def test_timeout_is_typed(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], 5)

        items, errors = KaliDiscovery(
            self.configured(),
            which=lambda name: "/usr/bin/ssh",
            runner=timeout,
        ).collect(live=True)
        self.assertFalse(items[0].reachable)
        self.assertEqual(errors[0].code, "kali_timeout")

    def test_tool_availability_versions_and_no_target_scan(self):
        calls = []
        tools = {
            name: {
                "available": name in {"nmap", "curl", "python3"},
                "version": "version 1" if name == "nmap" else None,
            }
            for name in KALI_TOOLS
        }

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "os": "Kali Linux",
                        "tools": tools,
                        "reverse_tunnel_capability": None,
                    }
                ),
                stderr="",
            )

        items, errors = KaliDiscovery(
            self.configured(),
            which=lambda name: "/usr/bin/ssh",
            runner=runner,
        ).collect(live=True)
        self.assertEqual(errors, [])
        item = items[0]
        self.assertTrue(item.reachable)
        self.assertEqual(
            next(tool for tool in item.tools if tool.name == "nmap").version,
            "version 1",
        )
        self.assertEqual(
            next(tool for tool in item.tools if tool.name == "nikto").state,
            ToolState.MISSING,
        )
        command, kwargs = calls[0]
        self.assertEqual(command[-2:], ["sh", "-s"])
        self.assertNotIn("nmap ", kwargs["input"])
        self.assertNotIn("127.0.0.1", kwargs["input"])
        self.assertNotIn("localhost", kwargs["input"])


if __name__ == "__main__":
    unittest.main()
