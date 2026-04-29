from __future__ import annotations

import pytest
import respx
from httpx import Response

from arcadia_auth.client import OidcClient
from arcadia_auth.config import OidcSettings
from arcadia_auth.exceptions import DiscoveryError


@pytest.fixture
def client(oidc_settings: OidcSettings) -> OidcClient:
    return OidcClient(oidc_settings)


@pytest.fixture
def initialized_client(oidc_settings: OidcSettings, discovery_data: dict) -> OidcClient:
    c = OidcClient(oidc_settings)
    c._endpoints = {  # noqa: SLF001
        "authorization_endpoint": discovery_data["authorization_endpoint"],
        "token_endpoint": discovery_data["token_endpoint"],
        "revocation_endpoint": discovery_data["revocation_endpoint"],
        "userinfo_endpoint": discovery_data["userinfo_endpoint"],
    }
    return c


@pytest.mark.asyncio
async def test_initialize_caches_endpoints(
    client: OidcClient,
    oidc_settings: OidcSettings,
    discovery_data: dict,
) -> None:
    with respx.mock:
        respx.get(
            f"{oidc_settings.oidc_base_url}/.well-known/openid-configuration"
        ).mock(return_value=Response(200, json=discovery_data))
        await client.initialize()
    assert client._endpoints["token_endpoint"] == discovery_data["token_endpoint"]  # noqa: SLF001


@pytest.mark.asyncio
async def test_initialize_raises_on_failure(
    oidc_settings: OidcSettings,
) -> None:
    settings = OidcSettings(
        oidc_endpoint=oidc_settings.oidc_endpoint,
        oidc_public_endpoint=oidc_settings.oidc_public_endpoint,
        oidc_realm=oidc_settings.oidc_realm,
        oidc_client_id=oidc_settings.oidc_client_id,
        oidc_client_secret=oidc_settings.oidc_client_secret,
        oidc_redirect_uri=oidc_settings.oidc_redirect_uri,
        oidc_init_retries=1,
        oidc_init_backoff=0.0,
    )
    c = OidcClient(settings)
    with respx.mock:
        respx.get(f"{settings.oidc_base_url}/.well-known/openid-configuration").mock(
            return_value=Response(503)
        )
        with pytest.raises(DiscoveryError):
            await c.initialize()


def test_authorization_url(initialized_client: OidcClient) -> None:
    url = initialized_client.authorization_url(
        redirect_uri="http://localhost/callback",
        state="abc123",
        scope="openid profile email",
    )
    assert "response_type=code" in url
    assert "state=abc123" in url
    assert "openid" in url


@pytest.mark.asyncio
async def test_fetch_tokens(
    initialized_client: OidcClient, oidc_settings: OidcSettings
) -> None:
    token_endpoint = initialized_client._endpoints["token_endpoint"].replace(  # noqa: SLF001
        oidc_settings.oidc_public_base_url, oidc_settings.oidc_base_url
    )
    with respx.mock:
        respx.post(token_endpoint).mock(
            return_value=Response(
                200,
                json={
                    "access_token": "at",
                    "refresh_token": "rt",
                    "expires_in": 300,
                    "token_type": "Bearer",
                },
            )
        )
        result = await initialized_client.fetch_tokens(
            "mycode", "http://localhost/callback"
        )
    assert result["access_token"] == "at"


@pytest.mark.asyncio
async def test_refresh_token(
    initialized_client: OidcClient, oidc_settings: OidcSettings
) -> None:
    token_endpoint = initialized_client._endpoints["token_endpoint"].replace(  # noqa: SLF001
        oidc_settings.oidc_public_base_url, oidc_settings.oidc_base_url
    )
    with respx.mock:
        respx.post(token_endpoint).mock(
            return_value=Response(
                200,
                json={
                    "access_token": "new_at",
                    "refresh_token": "new_rt",
                    "expires_in": 300,
                    "token_type": "Bearer",
                },
            )
        )
        result = await initialized_client.refresh_token("old_rt")
    assert result["access_token"] == "new_at"


@pytest.mark.asyncio
async def test_revoke_token_best_effort(
    initialized_client: OidcClient,
    oidc_settings: OidcSettings,
) -> None:
    import httpx as _httpx

    revoke_endpoint = initialized_client._endpoints["revocation_endpoint"].replace(  # noqa: SLF001
        oidc_settings.oidc_public_base_url, oidc_settings.oidc_base_url
    )
    with respx.mock:
        respx.post(revoke_endpoint).mock(side_effect=_httpx.ConnectError("down"))
        # Must not raise even on network failure
        await initialized_client.revoke_token("some_token")


@pytest.mark.asyncio
async def test_fetch_userinfo(
    initialized_client: OidcClient, oidc_settings: OidcSettings
) -> None:
    userinfo_endpoint = initialized_client._endpoints["userinfo_endpoint"].replace(  # noqa: SLF001
        oidc_settings.oidc_public_base_url, oidc_settings.oidc_base_url
    )
    with respx.mock:
        respx.get(userinfo_endpoint).mock(
            return_value=Response(200, json={"sub": "user-1", "email": "u@example.com"})
        )
        result = await initialized_client.fetch_userinfo("access_token_here")
    assert result["sub"] == "user-1"
