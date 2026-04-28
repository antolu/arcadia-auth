from __future__ import annotations

import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import Response

from arcadia_auth.config import OidcSettings
from arcadia_auth.exceptions import JwksError, TokenExpiredError, TokenInvalidError
from arcadia_auth.validator import OidcValidator
from tests.conftest import make_token


@pytest.fixture
def validator(oidc_settings: OidcSettings) -> OidcValidator:
    return OidcValidator(oidc_settings)


async def _init_validator(
    validator: OidcValidator,
    oidc_settings: OidcSettings,
    discovery_data: dict,
    jwks_data: dict,
) -> None:
    jwks_uri = discovery_data["jwks_uri"].replace(
        oidc_settings.oidc_public_base_url, oidc_settings.oidc_base_url
    )
    with respx.mock:
        respx.get(
            f"{oidc_settings.oidc_base_url}/.well-known/openid-configuration"
        ).mock(return_value=Response(200, json=discovery_data))
        respx.get(jwks_uri).mock(return_value=Response(200, json=jwks_data))
        await validator.initialize()


@pytest.mark.asyncio
async def test_initialize_fetches_jwks(
    validator: OidcValidator,
    oidc_settings: OidcSettings,
    discovery_data: dict,
    jwks_data: dict,
) -> None:
    await _init_validator(validator, oidc_settings, discovery_data, jwks_data)
    assert validator._keyset is not None  # noqa: SLF001


@pytest.mark.asyncio
async def test_validate_token_valid(
    oidc_settings: OidcSettings,
    rsa_private_key: rsa.RSAPrivateKey,
    discovery_data: dict,
    jwks_data: dict,
) -> None:
    validator = OidcValidator(oidc_settings)
    await _init_validator(validator, oidc_settings, discovery_data, jwks_data)
    token = make_token(rsa_private_key)
    payload = await validator.validate_token(token)
    assert payload["sub"] == "user-1"


@pytest.mark.asyncio
async def test_validate_token_expired(
    oidc_settings: OidcSettings,
    rsa_private_key: rsa.RSAPrivateKey,
    discovery_data: dict,
    jwks_data: dict,
) -> None:
    validator = OidcValidator(oidc_settings)
    await _init_validator(validator, oidc_settings, discovery_data, jwks_data)
    token = make_token(rsa_private_key, exp_offset=-10)
    with pytest.raises(TokenExpiredError):
        await validator.validate_token(token)


@pytest.mark.asyncio
async def test_validate_token_wrong_issuer(
    oidc_settings: OidcSettings,
    rsa_private_key: rsa.RSAPrivateKey,
    discovery_data: dict,
    jwks_data: dict,
) -> None:
    validator = OidcValidator(oidc_settings)
    await _init_validator(validator, oidc_settings, discovery_data, jwks_data)
    token = make_token(rsa_private_key, iss="http://evil.example.com")
    with pytest.raises(TokenInvalidError):
        await validator.validate_token(token)


@pytest.mark.asyncio
async def test_validate_token_tampered(
    oidc_settings: OidcSettings,
    rsa_private_key: rsa.RSAPrivateKey,
    discovery_data: dict,
    jwks_data: dict,
) -> None:
    validator = OidcValidator(oidc_settings)
    await _init_validator(validator, oidc_settings, discovery_data, jwks_data)
    token = make_token(rsa_private_key)[:-5] + "XXXXX"
    with pytest.raises(TokenInvalidError):
        await validator.validate_token(token)


@pytest.mark.asyncio
async def test_initialize_raises_on_discovery_failure(
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
    validator = OidcValidator(settings)
    with respx.mock:
        respx.get(f"{settings.oidc_base_url}/.well-known/openid-configuration").mock(
            return_value=Response(503)
        )
        with pytest.raises(JwksError):
            await validator.initialize()
