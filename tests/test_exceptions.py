from __future__ import annotations

from arcadia_auth.exceptions import (
    DiscoveryError,
    JwksError,
    OidcError,
    TokenExpiredError,
    TokenInvalidError,
)


def test_hierarchy() -> None:
    assert issubclass(DiscoveryError, OidcError)
    assert issubclass(JwksError, OidcError)
    assert issubclass(TokenExpiredError, OidcError)
    assert issubclass(TokenInvalidError, OidcError)


def test_exceptions_are_catchable_as_base() -> None:
    for cls in (DiscoveryError, JwksError, TokenExpiredError, TokenInvalidError):
        try:
            raise cls("test")
        except OidcError:
            pass
