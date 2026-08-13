from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from .contracts import ResponsePlanError, require_digest, require_identifier


def _safe_identity_text(value: object, *, code: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ResponsePlanError(code)
    return value


@dataclass(frozen=True, slots=True)
class VerifiedPrincipal:
    issuer: str
    subject: str
    audience: str
    kind: str
    roles: frozenset[str]
    incident_ids: frozenset[str]
    credential_sha256: str
    expires_at: datetime
    _trust_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "roles", frozenset(self.roles))
        object.__setattr__(self, "incident_ids", frozenset(self.incident_ids))
        _safe_identity_text(self.issuer, code="principal-issuer-invalid", maximum=512)
        _safe_identity_text(self.subject, code="principal-subject-invalid", maximum=255)
        _safe_identity_text(self.audience, code="principal-audience-invalid", maximum=255)
        if self.kind not in {"human", "service", "model"}:
            raise ResponsePlanError("principal-kind-invalid")
        for role in self.roles:
            require_identifier(role, code="principal-role-invalid")
        for incident_id in self.incident_ids:
            require_identifier(incident_id, code="principal-incident-invalid")
        require_digest(self.credential_sha256, code="principal-credential-invalid")
        if self.expires_at.tzinfo is None:
            raise ResponsePlanError("principal-expiry-invalid")
        object.__setattr__(self, "expires_at", self.expires_at.astimezone(UTC))

    def actor(self) -> dict[str, str]:
        if self.kind == "model":
            raise ResponsePlanError("model-authority-forbidden")
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "audience": self.audience,
            "kind": self.kind,
        }


class OIDCTrustBoundary:
    def __init__(self, *, trusted_issuers: frozenset[str], audience: str) -> None:
        if not trusted_issuers:
            raise ResponsePlanError("trusted-issuer-required")
        self._trusted_issuers = frozenset(
            _safe_identity_text(value, code="trusted-issuer-invalid", maximum=512)
            for value in trusted_issuers
        )
        self._audience = _safe_identity_text(audience, code="trusted-audience-invalid", maximum=255)
        self._trust_token = object()

    @property
    def audience(self) -> str:
        return self._audience

    def bind_verified_claims(
        self,
        *,
        issuer: str,
        subject: str,
        audience: str,
        kind: str,
        roles: frozenset[str],
        incident_ids: frozenset[str],
        credential_sha256: str,
        expires_at: datetime,
        credential_verified: bool,
        now: datetime,
    ) -> VerifiedPrincipal:
        if credential_verified is not True:
            raise ResponsePlanError("credential-not-verified")
        if issuer not in self._trusted_issuers:
            raise ResponsePlanError("principal-issuer-untrusted")
        if audience != self._audience:
            raise ResponsePlanError("principal-audience-untrusted")
        principal = VerifiedPrincipal(
            issuer=issuer,
            subject=subject,
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

    def assert_trusted(self, principal: VerifiedPrincipal, *, now: datetime) -> None:
        if not isinstance(principal, VerifiedPrincipal):
            raise ResponsePlanError("verified-principal-required")
        if principal._trust_token is not self._trust_token:
            raise ResponsePlanError("principal-trust-boundary-mismatch")
        if principal.issuer not in self._trusted_issuers:
            raise ResponsePlanError("principal-issuer-untrusted")
        if principal.audience != self._audience:
            raise ResponsePlanError("principal-audience-untrusted")
        if now.tzinfo is None:
            raise ResponsePlanError("invalid-time")
        if principal.expires_at <= now.astimezone(UTC):
            raise ResponsePlanError("principal-credential-expired")


__all__ = ["OIDCTrustBoundary", "VerifiedPrincipal"]
