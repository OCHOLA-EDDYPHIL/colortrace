from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

PrincipalKind = Literal["human", "service"]


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    display_name: str
    roles: frozenset[str]
    issuer: str
    audience: str
    principal_kind: PrincipalKind
    incident_ids: frozenset[str]
    credential_sha256: str
    expires_at: datetime


class TokenVerifier(Protocol):
    def verify(self, token: str) -> Principal: ...
