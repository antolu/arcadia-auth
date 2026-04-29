from __future__ import annotations

import asyncio
import logging
import typing
from urllib.parse import urlencode

import httpx

from arcadia_auth.config import OidcSettings
from arcadia_auth.exceptions import DiscoveryError, OidcError

logger = logging.getLogger(__name__)

_Endpoints = dict[str, str]


class OidcClient:
    def __init__(self, settings: OidcSettings) -> None:
        self._settings = settings
        self._endpoints: _Endpoints = {}

    async def initialize(self) -> None:
        retries = self._settings.oidc_init_retries
        backoff = self._settings.oidc_init_backoff
        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                await self._fetch_discovery()
            except DiscoveryError as exc:
                last_exc = exc
                if attempt < retries - 1:
                    await asyncio.sleep(backoff * (2**attempt))
            else:
                return
        msg = f"OIDC discovery failed after {retries} attempts"
        raise DiscoveryError(msg) from last_exc

    async def _fetch_discovery(self) -> None:
        url = f"{self._settings.oidc_base_url}/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                msg = f"Could not reach discovery endpoint: {exc}"
                raise DiscoveryError(msg) from exc
            if resp.status_code != 200:  # noqa: PLR2004
                msg = f"Discovery returned {resp.status_code}"
                raise DiscoveryError(msg)
            data = resp.json()
        try:
            self._endpoints = {
                "authorization_endpoint": data["authorization_endpoint"],
                "token_endpoint": data["token_endpoint"],
                "revocation_endpoint": data.get("revocation_endpoint", ""),
                "userinfo_endpoint": data["userinfo_endpoint"],
            }
        except KeyError as exc:
            msg = f"Discovery doc missing required field: {exc}"
            raise DiscoveryError(msg) from exc

    def _internal(self, url: str) -> str:
        return url.replace(
            self._settings.oidc_public_base_url, self._settings.oidc_base_url
        )

    def _require_endpoints(self) -> None:
        if not self._endpoints:
            msg = "OidcClient not initialized — call initialize() first"
            raise DiscoveryError(msg)

    def authorization_url(self, redirect_uri: str, state: str, scope: str) -> str:
        self._require_endpoints()
        params = urlencode({
            "client_id": self._settings.oidc_client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
        })
        return f"{self._endpoints['authorization_endpoint']}?{params}"

    async def fetch_tokens(self, code: str, redirect_uri: str) -> dict[str, typing.Any]:
        self._require_endpoints()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                self._internal(self._endpoints["token_endpoint"]),
                data={
                    "grant_type": "authorization_code",
                    "client_id": self._settings.oidc_client_id,
                    "client_secret": self._settings.oidc_client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
            )
        if resp.status_code != 200:  # noqa: PLR2004
            msg = f"Token exchange failed: {resp.status_code}"
            raise OidcError(msg)
        return typing.cast(dict[str, typing.Any], resp.json())

    async def refresh_token(self, refresh_token: str) -> dict[str, typing.Any]:
        self._require_endpoints()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                self._internal(self._endpoints["token_endpoint"]),
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": self._settings.oidc_client_id,
                    "client_secret": self._settings.oidc_client_secret,
                },
            )
        if resp.status_code != 200:  # noqa: PLR2004
            msg = f"Token refresh failed: {resp.status_code}"
            raise OidcError(msg)
        return typing.cast(dict[str, typing.Any], resp.json())

    async def revoke_token(self, token: str) -> None:
        self._require_endpoints()
        if not self._endpoints.get("revocation_endpoint"):
            return
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    self._internal(self._endpoints["revocation_endpoint"]),
                    data={
                        "token": token,
                        "client_id": self._settings.oidc_client_id,
                        "client_secret": self._settings.oidc_client_secret,
                    },
                )
        except Exception:
            logger.debug("Token revocation failed (best-effort, ignored)")

    async def fetch_userinfo(self, access_token: str) -> dict[str, typing.Any]:
        self._require_endpoints()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                self._internal(self._endpoints["userinfo_endpoint"]),
                headers={"Authorization": f"Bearer {access_token}"},
            )
        if resp.status_code != 200:  # noqa: PLR2004
            msg = f"Userinfo fetch failed: {resp.status_code}"
            raise OidcError(msg)
        return typing.cast(dict[str, typing.Any], resp.json())
