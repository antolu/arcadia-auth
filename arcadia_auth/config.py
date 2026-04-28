from __future__ import annotations

from pydantic_settings import BaseSettings


class OidcSettings(BaseSettings):
    oidc_endpoint: str
    oidc_public_endpoint: str
    oidc_realm: str
    oidc_client_id: str
    oidc_client_secret: str
    oidc_redirect_uri: str
    oidc_jwks_cache_ttl: int = 3600
    oidc_init_retries: int = 5
    oidc_init_backoff: float = 2.0

    @property
    def oidc_base_url(self) -> str:
        return f"{self.oidc_endpoint}/realms/{self.oidc_realm}"

    @property
    def oidc_public_base_url(self) -> str:
        return f"{self.oidc_public_endpoint}/realms/{self.oidc_realm}"

    @property
    def oidc_issuer_url(self) -> str:
        return self.oidc_public_base_url

    model_config = {"env_file": ".env", "extra": "ignore"}
