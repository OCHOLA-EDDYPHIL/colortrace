from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from .contracts import RecoveryError, require_digest, require_identifier

VERIFIER_ROLE = "recovery.verifier"
CLOSER_ROLE = "recovery.closer"


def _safe_text(value: object, *, code: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value.strip() != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise RecoveryError(code)
    return value


@dataclass(frozen=True, slots=True)
class RecoveryPrincipal:
    issuer: str
    subject: str
    display_name: str
    audience: str
    kind: Literal["human", "service", "model"]
    roles: frozenset[str]
    incident_ids: frozenset[str]
    credential_sha256: str
    expires_at: datetime
    _trust_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _safe_text(self.issuer, code="principal-issuer-invalid", maximum=512)
        _safe_text(self.subject, code="principal-subject-invalid", maximum=255)
        _safe_text(self.display_name, code="principal-display-name-invalid", maximum=256)
        _safe_text(self.audience, code="principal-audience-invalid", maximum=255)
        if self.kind not in {"human", "service", "model"}:
            raise RecoveryError("principal-kind-invalid")
        for role in self.roles:
            require_identifier(role, code="principal-role-invalid")
        for incident_id in self.incident_ids:
            require_identifier(incident_id, code="principal-incident-invalid")
        require_digest(self.credential_sha256, code="principal-credential-invalid")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise RecoveryError("principal-expiry-invalid")
        object.__setattr__(self, "roles", frozenset(self.roles))
        object.__setattr__(self, "incident_ids", frozenset(self.incident_ids))
        object.__setattr__(self, "expires_at", self.expires_at.astimezone(UTC))

    def actor(self, *, authorized_role: str) -> dict[str, str]:
        if self.kind == "model":
            raise RecoveryError("model-authority-forbidden")
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "audience": self.audience,
            "display_name": self.display_name,
            "kind": self.kind,
            "authorized_role": authorized_role,
        }


class RecoveryIdentityBoundary:
    def __init__(self, *, trusted_issuers: frozenset[str], audience: str) -> None:
        if not trusted_issuers:
            raise RecoveryError("trusted-issuer-required")
        self._trusted_issuers = frozenset(
            _safe_text(value, code="trusted-issuer-invalid", maximum=512)
            for value in trusted_issuers
        )
        self._audience = _safe_text(
            audience,
            code="trusted-audience-invalid",
            maximum=255,
        )
        self._trust_token = object()

    def bind_verified_claims(
        self,
        *,
        issuer: str,
        subject: str,
        display_name: str,
        audience: str,
        kind: Literal["human", "service", "model"],
        roles: frozenset[str],
        incident_ids: frozenset[str],
        credential_sha256: str,
        expires_at: datetime,
        credential_verified: bool,
        now: datetime,
    ) -> RecoveryPrincipal:
        if credential_verified is not True:
            raise RecoveryError("credential-not-verified")
        if issuer not in self._trusted_issuers:
            raise RecoveryError("principal-issuer-untrusted")
        if audience != self._audience:
            raise RecoveryError("principal-audience-untrusted")
        principal = RecoveryPrincipal(
            issuer=issuer,
            subject=subject,
            display_name=display_name,
            audience=audience,
            kind=kind,
            roles=roles,
            incident_ids=incident_ids,
            credential_sha256=credential_sha256,
            expires_at=expires_at,
            _trust_token=self._trust_token,
        )
        self.assert_trusted(principal, now=now)
        return principal

    def assert_trusted(self, principal: RecoveryPrincipal, *, now: datetime) -> None:
        if (
            not isinstance(principal, RecoveryPrincipal)
            or principal._trust_token is not self._trust_token
        ):
            raise RecoveryError("principal-trust-boundary-mismatch")
        if now.tzinfo is None or now.utcoffset() is None:
            raise RecoveryError("time-invalid")
        if principal.expires_at <= now.astimezone(UTC):
            raise RecoveryError("principal-credential-expired")

    def assert_verifier(
        self,
        principal: RecoveryPrincipal,
        *,
        incident_id: str,
        now: datetime,
    ) -> dict[str, str]:
        self.assert_trusted(principal, now=now)
        if principal.kind == "model":
            raise RecoveryError("model-authority-forbidden")
        if principal.kind != "service":
            raise RecoveryError("verifier-service-required")
        if VERIFIER_ROLE not in principal.roles:
            raise RecoveryError("verifier-role-required")
        if incident_id not in principal.incident_ids:
            raise RecoveryError("incident-access-denied")
        return principal.actor(authorized_role=VERIFIER_ROLE)

    def assert_closer(
        self,
        principal: RecoveryPrincipal,
        *,
        incident_id: str,
        now: datetime,
    ) -> dict[str, str]:
        self.assert_trusted(principal, now=now)
        if principal.kind == "model":
            raise RecoveryError("model-authority-forbidden")
        if principal.kind != "human":
            raise RecoveryError("closure-human-required")
        if CLOSER_ROLE not in principal.roles:
            raise RecoveryError("closer-role-required")
        if incident_id not in principal.incident_ids:
            raise RecoveryError("incident-access-denied")
        return principal.actor(authorized_role=CLOSER_ROLE)


__all__ = [
    "CLOSER_ROLE",
    "VERIFIER_ROLE",
    "RecoveryIdentityBoundary",
    "RecoveryPrincipal",
]
