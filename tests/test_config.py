from __future__ import annotations

import math

from arcadia_auth.config import OidcSettings


def test_derived_urls() -> None:
    s = OidcSettings(
        oidc_endpoint="http://keycloak:8080",
        oidc_public_endpoint="http://localhost:9091",
        oidc_realm="arcadia",
        oidc_client_id="myapp",
        oidc_client_secret="secret",
        oidc_redirect_uri="http://localhost/callback",
    )
    assert s.oidc_base_url == "http://keycloak:8080/realms/arcadia"
    assert s.oidc_public_base_url == "http://localhost:9091/realms/arcadia"
    assert s.oidc_issuer_url == "http://localhost:9091/realms/arcadia"


def test_defaults() -> None:
    s = OidcSettings(
        oidc_endpoint="http://keycloak:8080",
        oidc_public_endpoint="http://localhost:9091",
        oidc_realm="arcadia",
        oidc_client_id="myapp",
        oidc_client_secret="secret",
        oidc_redirect_uri="http://localhost/callback",
    )
    assert s.oidc_jwks_cache_ttl == 3600  # noqa: PLR2004
    assert s.oidc_init_retries == 5  # noqa: PLR2004
    assert math.isclose(s.oidc_init_backoff, 2.0)


def test_empty_construction_succeeds() -> None:
    s = OidcSettings()
    assert not s.oidc_endpoint
    assert not s.oidc_realm
