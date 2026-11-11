"""Importing this package registers every built-in check."""

from exposureguard.checks import (  # noqa: F401
    camera,
    default_credentials,
    exposed_paths,
    exposed_services,
    http_form_login,
    http_headers,
    industrial,
    network_services,
    profile_conformance,
    snmp_default,
    tls_posture,
)
