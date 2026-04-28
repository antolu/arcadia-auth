from __future__ import annotations

import asyncio
import logging
import time
import typing

import httpx
from authlib.jose import JsonWebKey, KeySet, jwt
from authlib.jose.errors import ExpiredTokenError, JoseError

from arcadia_auth.config import OidcSettings
from arcadia_auth.exceptions import DiscoveryError, JwksError, TokenExpiredError, TokenInvalidError

logger = logging.getLogger(__name__)


class OidcValidator:
    def __init__(self, settings: OidcSettings) -> None:
        self._settings = settings
        self._keyset: KeySet | None = None
        self._fetched_at: float = 0.0

    async def initialize(self) -> None:
        retries = self._settings.oidc_init_retries
        backoff = self._settings.oidc_init_backoff
        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                await self._refresh_keyset()
                return
            except (DiscoveryError, JwksError) as exc:
                last_exc = exc
                if attempt < retries - 1:
                    await asyncio.sleep(backoff * (2**attempt))
        raise JwksError(f"OIDC initialization failed after {retries} attempts") from last_exc

    async def _refresh_keyset(self) -> None:
        discovery_url = f"{self._settings.oidc_base_url}/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(discovery_url)
            except httpx.HTTPError as exc:
                raise DiscoveryError(f"Could not reach discovery endpoint: {exc}") from exc
            if resp.status_code != 200:
                raise DiscoveryError(f"Discovery returned {resp.status_code}")
            jwks_uri: str = resp.json().get("jwks_uri", "")
            if not jwks_uri:
                raise DiscoveryError("Discovery doc missing jwks_uri")

            jwks_uri = jwks_uri.replace(
                self._settings.oidc_public_base_url,
                self._settings.oidc_base_url,
            )

            try:
                jwks_resp = await client.get(jwks_uri)
            except httpx.HTTPError as exc:
                raise JwksError(f"Could not fetch JWKS: {exc}") from exc
            if jwks_resp.status_code != 200:
                raise JwksError(f"JWKS fetch returned {jwks_resp.status_code}")

            self._keyset = JsonWebKey.import_key_set(jwks_resp.json())
            self._fetched_at = time.monotonic()

    async def _ensure_keyset(self) -> KeySet:
        now = time.monotonic()
        if self._keyset is None or (now - self._fetched_at) > self._settings.oidc_jwks_cache_ttl:
            await self._refresh_keyset()
        if self._keyset is None:
            raise JwksError("JWKS unavailable")
        return self._keyset

    async def validate_token(self, token: str) -> dict[str, typing.Any]:
        keyset = await self._ensure_keyset()
        claims_options = {
            "iss": {"essential": True, "value": self._settings.oidc_issuer_url},
            "exp": {"essential": True},
            "sub": {"essential": True},
        }
        try:
            claims = jwt.decode(token, keyset, claims_options=claims_options)
            claims.validate()
        except ExpiredTokenError as exc:
            raise TokenExpiredError("Token has expired") from exc
        except JoseError as exc:
            raise TokenInvalidError(f"Token invalid: {exc}") from exc
        return dict(claims)
