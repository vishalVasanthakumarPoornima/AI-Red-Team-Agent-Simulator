"""Passive service probes represented in the same typed format."""

from redteam_platform.dexter.models import DexterProbe


def service_probes(target) -> list[DexterProbe]:
    return [
        DexterProbe(
            probe_id="DX-SVC-001",
            category="service_exposure",
            name="root_headers",
            method="GET",
            route=target.main_endpoint,
            expected_boundary="safe headers and bounded response",
        )
    ]
