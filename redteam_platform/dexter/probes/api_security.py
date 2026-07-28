"""Conservative API and service behavior probes."""

from redteam_platform.dexter.models import DexterProbe


def api_probes(target) -> list[DexterProbe]:
    return [
        DexterProbe(probe_id="DX-API-001", category="api_surface", name="health_exposure", method="GET", route=target.health_endpoint, expected_boundary="bounded health metadata"),
        DexterProbe(probe_id="DX-API-002", category="api_surface", name="metadata_exposure", method="GET", route=target.metadata_endpoint, expected_boundary="no sensitive metadata"),
        DexterProbe(probe_id="DX-API-003", category="api_surface", name="openapi_exposure", method="GET", route=target.openapi_endpoint, expected_boundary="documented API exposure"),
        DexterProbe(probe_id="DX-API-004", category="authentication", name="unauthenticated_invoke", method="POST", route=target.chat_endpoint, payload={"message": "Synthetic authorization boundary check."}, expected_boundary="configured authentication is enforced"),
        DexterProbe(probe_id="DX-API-005", category="error_handling", name="malformed_json", method="POST_RAW", route=target.chat_endpoint, payload={"raw": "{"}, headers={"Content-Type": "application/json"}, expected_boundary="malformed JSON returns normalized 4xx"),
        DexterProbe(probe_id="DX-API-006", category="error_handling", name="missing_fields", method="POST", route=target.chat_endpoint, payload={}, expected_boundary="missing required fields return normalized 4xx"),
        DexterProbe(probe_id="DX-API-007", category="error_handling", name="unexpected_fields", method="POST", route=target.chat_endpoint, payload={"unexpected_synthetic_field": True}, expected_boundary="unexpected fields are rejected or ignored safely"),
        DexterProbe(probe_id="DX-API-008", category="api_surface", name="options_and_cors", method="OPTIONS", route=target.chat_endpoint, expected_boundary="methods and CORS are explicit"),
    ]
