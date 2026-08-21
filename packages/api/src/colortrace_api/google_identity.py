from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

from .auth import Principal

_GOOGLE_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})
_SERVICE_ACCOUNT_EMAIL = re.compile(
    r"[a-z0-9][a-z0-9-]{0,62}@[a-z0-9][a-z0-9.-]{0,200}\.iam\.gserviceaccount\.com\Z"
)
_SUBJECT = re.compile(r"[0-9]{1,64}\Z")
_ROLE = re.compile(r"[a-z][a-z0-9._:-]{0,63}\Z")
_INCIDENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_MAX_TOKEN_BYTES = 16_384
_MAX_AUDIENCE_LENGTH = 2_048
_MAX_CLAIMS = 64
_MAX_LEEWAY_SECONDS = 120.0
_MAX_TOKEN_LIFETIME_SECONDS = 3_600.0
_GENERIC_FAILURE = "Google service token verification failed"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class GoogleServiceTokenError(ValueError):
    def __init__(self) -> None:
        super().__init__(_GENERIC_FAILURE)


class GoogleIdTokenClaimsVerifier(Protocol):
    def verify(
        self,
        token: str,
        *,
        audience: str,
        clock_skew_seconds: float,
    ) -> Mapping[str, object]: ...


class GoogleAuthIdTokenClaimsVerifier:
    def __init__(self, request: Any | None = None) -> None:
        self._request = request

    def verify(
        self,
        token: str,
        *,
        audience: str,
        clock_skew_seconds: float,
    ) -> Mapping[str, object]:
        from google.auth.transport.requests import Request
        from google.oauth2 import id_token

        request = Request() if self._request is None else self._request
        claims = id_token.verify_oauth2_token(  # type: ignore[no-untyped-call]
            token,
            request,
            audience=audience,
            clock_skew_in_seconds=int(clock_skew_seconds),
        )
        if not isinstance(claims, Mapping):
            raise ValueError("verified claims are not a mapping")
        return cast(Mapping[str, object], claims)


def _audience(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_AUDIENCE_LENGTH:
        raise ValueError("audience must be a bounded HTTPS URL")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("audience must be a bounded HTTPS URL") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port == 0
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("audience must be a bounded HTTPS URL")
    return value


def _leeway(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("leeway_seconds must be numeric")
    selected = float(value)
    if not math.isfinite(selected) or not 0 <= selected <= _MAX_LEEWAY_SECONDS:
        raise ValueError("leeway_seconds is outside its supported range")
    return selected


def _numeric_date(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
    ):
        raise ValueError("invalid numeric date")
    return float(value)


@dataclass(frozen=True, slots=True)
class GoogleServiceIdentity:
    issuer: str
    subject: str
    email: str
    audience: str
    credential_sha256: str
    expires_at: datetime


class GoogleOidcTokenVerifier:
    def __init__(
        self,
        *,
        audience: str,
        claims_verifier: GoogleIdTokenClaimsVerifier | None = None,
        leeway_seconds: float = 30.0,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._audience = _audience(audience)
        self._claims_verifier = claims_verifier or GoogleAuthIdTokenClaimsVerifier()
        self._leeway_seconds = _leeway(leeway_seconds)
        self._clock = clock

    @property
    def audience(self) -> str:
        return self._audience

    def verify(self, token: str) -> GoogleServiceIdentity:
        try:
            encoded = token.encode("ascii")
            if not encoded or len(encoded) > _MAX_TOKEN_BYTES:
                raise ValueError("invalid token length")
            claims = self._claims_verifier.verify(
                token,
                audience=self._audience,
                clock_skew_seconds=self._leeway_seconds,
            )
            if not isinstance(claims, Mapping) or not 1 <= len(claims) <= _MAX_CLAIMS:
                raise ValueError("invalid claims")
            if any(
                not isinstance(key, str)
                or not key
                or len(key) > 128
                or (isinstance(value, str) and len(value) > 4_096)
                for key, value in claims.items()
            ):
                raise ValueError("invalid claims")
            issuer = claims.get("iss")
            subject = claims.get("sub")
            email = claims.get("email")
            audience = claims.get("aud")
            if issuer not in _GOOGLE_ISSUERS:
                raise ValueError("invalid issuer")
            if audience != self._audience:
                raise ValueError("invalid audience")
            if not isinstance(subject, str) or _SUBJECT.fullmatch(subject) is None:
                raise ValueError("invalid subject")
            if (
                not isinstance(email, str)
                or _SERVICE_ACCOUNT_EMAIL.fullmatch(email) is None
                or claims.get("email_verified") is not True
            ):
                raise ValueError("invalid service account email")
            issued_at = _numeric_date(claims.get("iat"))
            expires_at = _numeric_date(claims.get("exp"))
            now = self._clock()
            if now.tzinfo is None or now.utcoffset() is None:
                raise ValueError("invalid clock")
            now_timestamp = now.astimezone(UTC).timestamp()
            if (
                issued_at > now_timestamp + self._leeway_seconds
                or expires_at <= now_timestamp - self._leeway_seconds
                or expires_at <= issued_at
                or expires_at - issued_at > _MAX_TOKEN_LIFETIME_SECONDS + (2 * self._leeway_seconds)
            ):
                raise ValueError("invalid token lifetime")
            return GoogleServiceIdentity(
                issuer=issuer,
                subject=subject,
                email=email,
                audience=self._audience,
                credential_sha256=f"sha256:{sha256(encoded).hexdigest()}",
                expires_at=datetime.fromtimestamp(expires_at, tz=UTC),
            )
        except Exception:
            raise GoogleServiceTokenError from None


class GoogleServiceIdentityVerifier(Protocol):
    def verify(self, token: str) -> GoogleServiceIdentity: ...


@dataclass(frozen=True, slots=True)
class ServerOwnedServiceBinding:
    caller_email: str
    audience: str
    role: str

    def __post_init__(self) -> None:
        if _SERVICE_ACCOUNT_EMAIL.fullmatch(self.caller_email) is None:
            raise ValueError("caller_email must identify one Google service account")
        object.__setattr__(self, "audience", _audience(self.audience))
        if _ROLE.fullmatch(self.role) is None:
            raise ValueError("role must be a bounded server-owned role")

    def bind(self, identity: GoogleServiceIdentity, *, incident_id: str) -> Principal:
        if (
            not isinstance(identity, GoogleServiceIdentity)
            or identity.issuer not in _GOOGLE_ISSUERS
            or identity.email != self.caller_email
            or identity.audience != self.audience
            or _INCIDENT_ID.fullmatch(incident_id) is None
        ):
            raise GoogleServiceTokenError
        return Principal(
            subject=identity.subject,
            display_name=identity.email,
            roles=frozenset({self.role}),
            issuer=identity.issuer,
            audience=identity.audience,
            principal_kind="service",
            incident_ids=frozenset({incident_id}),
            credential_sha256=identity.credential_sha256,
            expires_at=identity.expires_at,
        )


__all__ = [
    "GoogleAuthIdTokenClaimsVerifier",
    "GoogleIdTokenClaimsVerifier",
    "GoogleOidcTokenVerifier",
    "GoogleServiceIdentity",
    "GoogleServiceIdentityVerifier",
    "GoogleServiceTokenError",
    "ServerOwnedServiceBinding",
]
