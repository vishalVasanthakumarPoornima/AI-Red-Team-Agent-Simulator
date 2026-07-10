import unittest

from agent_lab_server import AgentLabError, resolve_allowed_targets
from agent_service import AgentServiceError, resolve_target


class ServiceResolutionTests(unittest.TestCase):
    def test_lab_server_rejects_unmarked_placeholder_target(self):
        with self.assertRaises(AgentLabError):
            resolve_allowed_targets(("dexter_agent",))

    def test_single_agent_service_rejects_unmarked_placeholder_target(self):
        with self.assertRaises(AgentServiceError):
            resolve_target("dexter_agent")

    def test_single_agent_service_resolves_marked_target(self):
        target = resolve_target("travel_agent")

        self.assertEqual(target["name"], "travel_agent")


if __name__ == "__main__":
    unittest.main()
