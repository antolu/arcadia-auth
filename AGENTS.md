# arcadia-auth

Shared Keycloak/OIDC authentication library for Arcadia server apps. Exposes `OidcClient` (OAuth 2.0 authorization code flow) and `OidcValidator` (JWT verification via JWKS). Not published to PyPI — install via `git+`.

## Package structure

```
arcadia_auth/
  __init__.py      # public API: OidcClient, OidcValidator, OidcSettings, exceptions
  client.py        # async OAuth 2.0 client
  validator.py     # async JWT validator with JWKS caching
  config.py        # OidcSettings (pydantic-settings)
  exceptions.py    # OidcError, DiscoveryError, JwksError, TokenExpiredError, TokenInvalidError
```

## Development

```bash
pip install -e ".[test,dev]"
pre-commit install
pytest
```

## Code conventions

- Python 3.11+, async-first (httpx, asyncio)
- `from __future__ import annotations` in every file
- Type hints everywhere; mypy strict (`disallow_untyped_defs`)
- `import xxx.yyy` for third-party libs, `from xxx.yyy import Zzz` for intra-package
- Imports at the top of every file
- No wildcard imports
- No unnecessary comments
- Functional tests (`def test_something`), not class-based
- Line length 88 (ruff/black)

## Linting and formatting

Pre-commit runs ruff and mypy. Always run `pre-commit run --files <changed files>` before committing. Never commit with `--no-verify`.

```bash
pre-commit run --files arcadia_auth/client.py
```

Ruff lint invocation (if running standalone): `ruff check --fix --unsafe-fixes --preview`

## Testing

Uses pytest with pytest-asyncio and respx (HTTP mocking). Run the full suite:

```bash
pytest
```

Tests live in `tests/`. Fixtures for RSA keys, mock OIDC discovery, and JWT generation are in `tests/conftest.py`.

## Commit style

Conventional commits: `feat:`, `fix:`, `refactor:`, `test:`, `ci:`, `chore:`. Keep messages short — describe what changed, not why.

## Design notes

- Both `OidcClient` and `OidcValidator` require `await initialize()` before use. Wire this into your app's lifespan/startup hook.
- `OidcClient` translates public OIDC URLs to internal URLs automatically — `oidc_endpoint` is for service-to-service, `oidc_public_endpoint` appears in browser redirect URLs.
- JWKS is cached in `OidcValidator` for `oidc_jwks_cache_ttl` seconds (default 3600). Cache is refreshed lazily on next validation after expiry.
- Token revocation (`OidcClient.revoke_token`) is best-effort: errors are logged but not raised.
