import unittest

from red_team_assistant import interpret_request


class RedTeamAssistantIntentTests(unittest.TestCase):
    def test_discovers_active_agents_from_natural_language(self):
        intent = interpret_request("find active agents running on this same machine")

        self.assertEqual(intent.action, "discover_agents")

    def test_master_assessment_from_attack_all_request(self):
        intent = interpret_request("attack all local agents and generate an enterprise report")

        self.assertEqual(intent.action, "master_assessment")
        self.assertTrue(intent.enterprise_report)

    def test_attack_active_running_agents_is_not_discovery_only(self):
        intent = interpret_request("attack active running agents and generate an enterprise report")

        self.assertEqual(intent.action, "attack_active_agents")
        self.assertTrue(intent.enterprise_report)

    def test_adaptive_request_extracts_target_and_payload_count(self):
        intent = interpret_request("run adaptive local red team against travel_agent with 3 payloads")

        self.assertEqual(intent.action, "local_red_team")
        self.assertEqual(intent.target, "travel_agent")
        self.assertEqual(intent.max_payloads, 3)

    def test_kali_attack_request_uses_kali_action(self):
        intent = interpret_request("run the ThinkPad Kali assessment")

        self.assertEqual(intent.action, "kali_attack")
        self.assertTrue(intent.include_kali)

    def test_full_assessment_with_kali_uses_master_pipeline(self):
        intent = interpret_request("full assessment with Kali and enterprise report")

        self.assertEqual(intent.action, "master_assessment")
        self.assertTrue(intent.include_kali)
        self.assertTrue(intent.enterprise_report)

    def test_comprehensive_demo_enables_dynamic_adaptive_and_kali_paths(self):
        intent = interpret_request("run a comprehensive dynamic demo assessment")

        self.assertEqual(intent.action, "master_assessment")
        self.assertTrue(intent.include_kali)
        self.assertTrue(intent.include_adaptive)
        self.assertTrue(intent.enterprise_report)


if __name__ == "__main__":
    unittest.main()
