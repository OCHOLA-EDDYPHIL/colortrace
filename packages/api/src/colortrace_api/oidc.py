from __future__ import annotations

import math
import re
from collections.abc import Mapping
from typing import Protocol, cast
from urllib.parse import urlsplit

from jwt import PyJWK, PyJWKClient, decode, get_unverified_header
from jwt.types import Options

from .auth import Principal, PrincipalKind

_ALGORITHM = "RS256"
_GENERIC_FAILURE = "OIDC token verification failed"
_MAX_TOKEN_BYTES = 16_384
_MAX_HEADER_FIELDS = 8
_MAX_KID_LENGTH = 128
_MAX_CLAIMS = 64
_MAX_CLAIM_DEPTH = 4
_MAX_CLAIM_NODES = 256
_MAX_CLAIM_COLLECTION_ITEMS = 64
_MAX_CLAIM_KEY_LENGTH = 128
_MAX_CLAIM_STRING_LENGTH = 4_096
_MAX_SUBJECT_LENGTH = 256
_MAX_DISPLAY_NAME_LENGTH = 256
_MAX_ROLES = 16
_MAX_ROLE_LENGTH = 64
_MAX_LEEWAY_SECONDS = 120.0
_MAX_URL_LENGTH = 2_048
_ROLE_PATTERN = re.compile(r"[a-z][a-z0-9._:-]*\Z")


class OidcVerificationError(ValueError):
    def __init__(self) -> None:
        super().__init__(_GENERIC_FAILURE)


class JwksResolver(Protocol):
    def resolve(self, kid: str) -> PyJWK: ...


def _bounded_number(value: float, *, maximum: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be numeric")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0 or normalized > maximum:
        raise ValueError(f"{name} is outside its supported range")
    return normalized


def _https_url(value: str, *, name: str, allow_query: bool) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_URL_LENGTH:
        raise ValueError(f"{name} must be a bounded HTTPS URL")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{name} must be a bounded HTTPS URL") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port == 0
        or parsed.fragment
        or (parsed.query and not allow_query)
    ):
        raise ValueError(f"{name} must be a bounded HTTPS URL")
    return value


class HttpsJwksResolver:
    @staticmethod
    def validate_uri(jwks_uri: str) -> str:
        return _https_url(jwks_uri, name="jwks_uri", allow_query=True)

    def __init__(
        self,
        jwks_uri: str,
        *,
        timeout_seconds: float = 5.0,
        cache_lifespan_seconds: float = 300.0,
    ) -> None:
        uri = self.validate_uri(jwks_uri)
        timeout = _bounded_number(
            timeout_seconds,
            maximum=10.0,
            name="timeout_seconds",
        )
        lifespan = _bounded_number(
            cache_lifespan_seconds,
            maximum=3_600.0,
            name="cache_lifespan_seconds",
        )
        if timeout == 0 or lifespan == 0:
            raise ValueError("JWKS timeout and cache lifespan must be positive")
        self._client = PyJWKClient(
            uri,
            cache_keys=True,
            max_cached_keys=16,
            cache_jwk_set=True,
            lifespan=lifespan,
            timeout=timeout,
        )

    def resolve(self, kid: str) -> PyJWK:
        return self._client.get_signing_key(kid)


def _bounded_claims(claims: Mapping[str, object]) -> bool:
    if len(claims) > _MAX_CLAIMS:
        return False
    stack: list[tuple[object, int]] = [(claims, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_CLAIM_NODES or depth > _MAX_CLAIM_DEPTH:
            return False
        if isinstance(value, str):
            if len(value) > _MAX_CLAIM_STRING_LENGTH:
                return False
            continue
        if isinstance(value, Mapping):
            if len(value) > _MAX_CLAIM_COLLECTION_ITEMS:
                return False
            for key, child in value.items():
                if not isinstance(key, str) or not key or len(key) > _MAX_CLAIM_KEY_LENGTH:
                    return False
                stack.append((child, depth + 1))
            continue
        if isinstance(value, list):
            if len(value) > _MAX_CLAIM_COLLECTION_ITEMS:
                return False
            stack.extend((child, depth + 1) for child in value)
            continue
        if value is None or isinstance(value, bool) or isinstance(value, int):
            continue
        if isinstance(value, float) and math.isfinite(value):
            continue
        return False
    return True


def _numeric_date(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(float(value))
    )


def _subject(claims: Mapping[str, object]) -> str:
    value = claims.get("sub")
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_SUBJECT_LENGTH
        or value.strip() != value
    ):
        raise ValueError("invalid subject")
    return value


def _display_name(claims: Mapping[str, object], subject: str) -> str:
    value = claims.get("name", subject)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_DISPLAY_NAME_LENGTH
        or value.strip() != value
    ):
        raise ValueError("invalid display name")
    return value


def _roles(claims: Mapping[str, object]) -> frozenset[str]:
    value = claims.get("roles")
    if not isinstance(value, list) or not 1 <= len(value) <= _MAX_ROLES:
        raise ValueError("invalid roles")
    roles: list[str] = []
    for role in value:
        if (
            not isinstance(role, str)
            or not role
            or len(role) > _MAX_ROLE_LENGTH
            or _ROLE_PATTERN.fullmatch(role) is None
        ):
            raise ValueError("invalid roles")
        roles.append(role)
    if len(set(roles)) != len(roles):
        raise ValueError("invalid roles")
    return frozenset(roles)


def _principal_kind(claims: Mapping[str, object]) -> PrincipalKind:
    value = claims.get("principal_kind")
    if value not in {"human", "service"}:
        raise ValueError("invalid principal kind")
    return value


class OidcTokenVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        resolver: JwksResolver,
        leeway_seconds: float = 30.0,
    ) -> None:
        self._issuer = _https_url(issuer, name="issuer", allow_query=False)
        if (
            not isinstance(audience, str)
            or not audience
            or len(audience) > _MAX_CLAIM_STRING_LENGTH
        ):
            raise ValueError("audience must be a bounded string")
        self._audience = audience
        self._resolver = resolver
        self._leeway_seconds = _bounded_number(
            leeway_seconds,
            maximum=_MAX_LEEWAY_SECONDS,
            name="leeway_seconds",
        )

    def verify(self, token: str) -> Principal:
        try:
            encoded = token.encode("ascii")
            if not encoded or len(encoded) > _MAX_TOKEN_BYTES:
                raise ValueError("invalid token length")
            header = cast(Mapping[str, object], get_unverified_header(token))
            if len(header) > _MAX_HEADER_FIELDS or header.get("alg") != _ALGORITHM:
                raise ValueError("invalid header")
            if "crit" in header:
                raise ValueError("unsupported critical header")
            kid = header.get("kid")
            if (
                not isinstance(kid, str)
                or not kid
                or len(kid) > _MAX_KID_LENGTH
                or not kid.isascii()
            ):
                raise ValueError("invalid key identifier")
            signing_key = self._resolver.resolve(kid)
            if signing_key.key_type != "RSA" or signing_key.algorithm_name != _ALGORITHM:
                raise ValueError("invalid signing key")
            options: Options = {
                "enforce_minimum_key_length": True,
                "require": [
                    "iss",
                    "aud",
                    "exp",
                    "iat",
                    "sub",
                    "roles",
                    "principal_kind",
                ],
                "strict_aud": False,
                "verify_aud": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_iss": True,
                "verify_nbf": True,
                "verify_signature": True,
                "verify_sub": True,
            }
            claims = cast(
                Mapping[str, object],
                decode(
                    token,
                    key=signing_key,
                    algorithms=[_ALGORITHM],
                    options=options,
                    audience=self._audience,
                    issuer=self._issuer,
                    leeway=self._leeway_seconds,
                ),
            )
            if not _bounded_claims(claims):
                raise ValueError("claims exceeded bounds")
            if not _numeric_date(claims.get("exp")) or not _numeric_date(claims.get("iat")):
                raise ValueError("invalid temporal claims")
            if "nbf" in claims and not _numeric_date(claims["nbf"]):
                raise ValueError("invalid not-before claim")
            subject = _subject(claims)
            return Principal(
                subject=subject,
                display_name=_display_name(claims, subject),
                roles=_roles(claims),
                issuer=self._issuer,
                audience=self._audience,
                principal_kind=_principal_kind(claims),
            )
        except Exception:
            raise OidcVerificationError from None
