# arcadia-auth

Shared Keycloak/OIDC authentication library for Arcadia server applications. Provides an async OAuth 2.0 client for authorization code flows and a JWT validator for token verification.

## Installation

This package is not published to PyPI. Install directly from the repository:

```bash
pip install git+https://github.com/antolu/arcadia-auth.git
```

To pin a specific version or commit:

```bash
pip install git+https://github.com/antolu/arcadia-auth.git@v0.1.0
pip install git+https://github.com/antolu/arcadia-auth.git@abc1234
```

In a `requirements.txt` or `pyproject.toml`:

```
arcadia-auth @ git+https://github.com/antolu/arcadia-auth.git@v0.1.0
```

## Requirements

- Python 3.11+
- A running Keycloak instance (or any OIDC-compatible provider)

## Configuration

All settings are loaded via `OidcSettings`, a Pydantic `BaseSettings` class that reads from environment variables or a `.env` file.

```python
from arcadia_auth import OidcSettings

settings = OidcSettings(
    oidc_endpoint="http://keycloak:8080",        # internal endpoint (service-to-service)
    oidc_public_endpoint="http://localhost:9091", # public endpoint (browser-facing)
    oidc_realm="my-realm",
    oidc_client_id="my-client",
    oidc_client_secret="secret",
    oidc_redirect_uri="http://localhost:8000/auth/callback",
)
```

Or via environment variables:

```bash
OIDC_ENDPOINT=http://keycloak:8080
OIDC_PUBLIC_ENDPOINT=http://localhost:9091
OIDC_REALM=my-realm
OIDC_CLIENT_ID=my-client
OIDC_CLIENT_SECRET=secret
OIDC_REDIRECT_URI=http://localhost:8000/auth/callback
```

### Settings reference

| Field | Type | Default | Description |
|---|---|---|---|
| `oidc_endpoint` | `str` | | Internal OIDC server URL (used for service-to-service calls) |
| `oidc_public_endpoint` | `str` | | Public OIDC server URL (used in browser redirect URLs) |
| `oidc_realm` | `str` | | Keycloak realm name |
| `oidc_client_id` | `str` | | OAuth client ID |
| `oidc_client_secret` | `str` | | OAuth client secret |
| `oidc_redirect_uri` | `str` | | Default OAuth redirect URI |
| `oidc_jwks_cache_ttl` | `int` | `3600` | JWKS cache TTL in seconds |
| `oidc_init_retries` | `int` | `5` | Retries for initialization |
| `oidc_init_backoff` | `float` | `2.0` | Exponential backoff multiplier for retries |

`oidc_base_url`, `oidc_public_base_url`, and `oidc_issuer_url` are derived properties and do not need to be set.

## Usage

### OAuth 2.0 authorization code flow

`OidcClient` handles the browser-facing OAuth flow: building authorization URLs, exchanging codes for tokens, refreshing tokens, and fetching user info.

```python
import asyncio
from arcadia_auth import OidcClient, OidcSettings

settings = OidcSettings()
client = OidcClient(settings)

async def main() -> None:
    # Must be called once before using the client
    await client.initialize()

    # Build the login redirect URL
    url = client.authorization_url(
        redirect_uri="http://localhost:8000/auth/callback",
        state="random-csrf-token",
        scope="openid profile email",
    )
    # Redirect the user's browser to `url`

    # After the user logs in, Keycloak redirects to your callback with ?code=...&state=...
    tokens = await client.fetch_tokens(
        code="authorization-code-from-callback",
        redirect_uri="http://localhost:8000/auth/callback",
    )
    # tokens: {"access_token": "...", "refresh_token": "...", "id_token": "...", ...}

    # Refresh an access token
    new_tokens = await client.refresh_token(tokens["refresh_token"])

    # Fetch user info
    userinfo = await client.fetch_userinfo(tokens["access_token"])
    # userinfo: {"sub": "...", "email": "...", "name": "...", ...}

    # Revoke a token on logout (best-effort, errors are logged but not raised)
    await client.revoke_token(tokens["refresh_token"])

asyncio.run(main())
```

### FastAPI example

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from arcadia_auth import OidcClient, OidcSettings

settings = OidcSettings()
client = OidcClient(settings)

@asynccontextmanager
async def lifespan(app: FastAPI):
    await client.initialize()
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/login")
async def login():
    url = client.authorization_url(
        redirect_uri=settings.oidc_redirect_uri,
        state="some-state",
        scope="openid profile email",
    )
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url)

@app.get("/auth/callback")
async def callback(code: str, state: str):
    tokens = await client.fetch_tokens(code, settings.oidc_redirect_uri)
    return tokens
```

### JWT token validation

`OidcValidator` validates bearer tokens on protected API endpoints. It fetches the JWKS from Keycloak and caches it for `oidc_jwks_cache_ttl` seconds.

```python
import asyncio
from arcadia_auth import OidcValidator, OidcSettings

settings = OidcSettings()
validator = OidcValidator(settings)

async def main() -> None:
    # Must be called once before validating tokens
    await validator.initialize()

    token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
    claims = await validator.validate_token(token)
    # claims: {"sub": "user-id", "iss": "...", "exp": 1234567890, ...}

asyncio.run(main())
```

### FastAPI dependency example

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from arcadia_auth import OidcValidator, OidcSettings, TokenExpiredError, TokenInvalidError

settings = OidcSettings()
validator = OidcValidator(settings)
bearer = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> dict:
    try:
        return await validator.validate_token(credentials.credentials)
    except TokenExpiredError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except TokenInvalidError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

app = FastAPI()

@app.get("/protected")
async def protected(claims: dict = Depends(get_current_user)):
    return {"user": claims["sub"]}
```

## Exceptions

All exceptions inherit from `OidcError`.

| Exception | When raised |
|---|---|
| `OidcError` | Base class for all errors in this library |
| `DiscoveryError` | OIDC discovery endpoint is unreachable or returns an unexpected response |
| `JwksError` | JWKS endpoint is unreachable or returns an unexpected response |
| `TokenExpiredError` | JWT `exp` claim is in the past |
| `TokenInvalidError` | JWT signature is invalid, issuer does not match, or required claims are missing |

## Development

```bash
git clone https://github.com/antolu/arcadia-auth.git
cd arcadia-auth
pip install -e ".[test,dev]"
pre-commit install
pytest
```
