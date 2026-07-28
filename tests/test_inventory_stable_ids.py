import unittest

from redteam_platform.inventory.platform import (
    listener_id,
    normalize_identity_url,
    stable_id,
)


class StableIdentifierTests(unittest.TestCase):
    def test_same_identity_is_stable_and_different_endpoints_differ(self):
        first = stable_id("http_service", "HTTP://LOCALHOST:80/")
        second = stable_id("http_service", "http://localhost")
        other = stable_id("http_service", "http://localhost:8000")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)

    def test_credentials_do_not_affect_or_leak_into_url_id(self):
        authenticated = stable_id(
            "service", "http://user:super-secret@localhost:8000/path?token=value"
        )
        clean = stable_id("service", "http://localhost:8000/path")
        self.assertEqual(authenticated, clean)
        self.assertNotIn("secret", authenticated)
        self.assertNotIn("user", authenticated)

    def test_ipv6_urls_and_listener_ids_are_normalized(self):
        self.assertEqual(
            normalize_identity_url("HTTP://[0:0:0:0:0:0:0:1]:80/"),
            "http://[::1]",
        )
        first = listener_id("tcp", "0:0:0:0:0:0:0:1", 8000, "python", "/python")
        second = listener_id("TCP", "::1", 8000, "python", "/python")
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
