from __future__ import annotations


class OidcError(Exception):
    pass


class DiscoveryError(OidcError):
    pass


class JwksError(OidcError):
    pass


class TokenExpiredError(OidcError):
    pass


class TokenInvalidError(OidcError):
    pass
