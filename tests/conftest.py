from __future__ import annotations

import base64
import time

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from arcadia_auth.config import OidcSettings


@pytest.fixture(scope="session")
def rsa_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def rsa_public_key(rsa_private_key: rsa.RSAPrivateKey) -> rsa.RSAPublicKey:
    return rsa_private_key.public_key()


@pytest.fixture(scope="session")
def jwks_data(rsa_public_key: rsa.RSAPublicKey) -> dict:
    pub_numbers = rsa_public_key.public_numbers()

    def int_to_base64url(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": "test-key-1",
                "n": int_to_base64url(pub_numbers.n),
                "e": int_to_base64url(pub_numbers.e),
            }
        ]
    }


@pytest.fixture(scope="session")
def oidc_settings() -> OidcSettings:
    return OidcSettings(
        oidc_endpoint="http://keycloak:8080",
        oidc_public_endpoint="http://localhost:9091",
        oidc_realm="arcadia",
        oidc_client_id="myapp",
        oidc_client_secret="secret",
        oidc_redirect_uri="http://localhost/callback",
    )


@pytest.fixture(scope="session")
def discovery_data(oidc_settings: OidcSettings) -> dict:
    base = oidc_settings.oidc_public_base_url
    return {
        "issuer": oidc_settings.oidc_issuer_url,
        "authorization_endpoint": f"{base}/protocol/openid-connect/auth",
        "token_endpoint": f"{base}/protocol/openid-connect/token",
        "userinfo_endpoint": f"{base}/protocol/openid-connect/userinfo",
        "end_session_endpoint": f"{base}/protocol/openid-connect/logout",
        "revocation_endpoint": f"{base}/protocol/openid-connect/revoke",
        "jwks_uri": f"{base}/protocol/openid-connect/certs",
    }


def make_token(
    private_key: rsa.RSAPrivateKey,
    *,
    sub: str = "user-1",
    iss: str = "http://localhost:9091/realms/arcadia",
    exp_offset: int = 3600,
) -> str:

    priv_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    now = int(time.time())
    return pyjwt.encode(
        {
            "sub": sub,
            "iss": iss,
            "exp": now + exp_offset,
            "iat": now,
            "jti": "test-jti",
        },
        priv_bytes,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )
