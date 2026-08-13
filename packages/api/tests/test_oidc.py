from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from time import time

import jwt
import pytest
from colortrace_api import (
    HttpsJwksResolver,
    OidcTokenVerifier,
    OidcVerificationError,
    Principal,
)
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK

ISSUER = "https://identity.example.test/tenant"
AUDIENCE = "colortrace-api"
KEY_ID = "test-key-1"


@dataclass(frozen=True, slots=True)
class KeyMaterial:
    private_key: rsa.RSAPrivateKey
    public_jwk: PyJWK


class LocalResolver:
    def __init__(self, keys: Mapping[str, PyJWK]) -> None:
        self._keys = dict(keys)
        self.calls: list[str] = []

    def resolve(self, kid: str) -> PyJWK:
        self.calls.append(kid)
        return self._keys[kid]


@pytest.fixture(scope="module")
def key_material() -> KeyMaterial:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    encoded = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    assert isinstance(encoded, dict)
    encoded.update({"alg": "RS256", "kid": KEY_ID, "use": "sig"})
    return KeyMaterial(private_key, PyJWK.from_dict(encoded))


def claims() -> dict[str, object]:
    now = int(time())
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now + 300,
        "iat": now - 1,
        "sub": "operator@example.test",
        "name": "Pipeline TD",
        "roles": ["pipeline_td", "response-plan.approver"],
        "principal_kind": "human",
    }


def token(
    material: KeyMaterial,
    *,
    updates: Mapping[str, object] | None = None,
    remove: tuple[str, ...] = (),
    kid: str | None = KEY_ID,
) -> str:
    payload = claims()
    if updates is not None:
        payload.update(updates)
    for claim in remove:
        payload.pop(claim, None)
    headers = {} if kid is None else {"kid": kid}
    return jwt.encode(payload, material.private_key, algorithm="RS256", headers=headers)


def verifier(material: KeyMaterial, *, leeway_seconds: float = 0) -> OidcTokenVerifier:
    return OidcTokenVerifier(
        issuer=ISSUER,
        audience=AUDIENCE,
        resolver=LocalResolver({KEY_ID: material.public_jwk}),
        leeway_seconds=leeway_seconds,
    )


def assert_rejected(subject: OidcTokenVerifier, encoded: str) -> None:
    with pytest.raises(
        OidcVerificationError,
        match="^OIDC token verification failed$",
    ) as error:
        subject.verify(encoded)
    assert error.value.__cause__ is None


def test_valid_token_projects_typed_identity(key_material: KeyMaterial) -> None:
    principal = verifier(key_material).verify(token(key_material))

    assert principal == Principal(
        subject="operator@example.test",
        display_name="Pipeline TD",
        roles=frozenset({"pipeline_td", "response-plan.approver"}),
        issuer=ISSUER,
        audience=AUDIENCE,
        principal_kind="human",
    )


def test_rejects_non_rs256_algorithm_before_key_resolution(key_material: KeyMaterial) -> None:
    resolver = LocalResolver({KEY_ID: key_material.public_jwk})
    subject = OidcTokenVerifier(issuer=ISSUER, audience=AUDIENCE, resolver=resolver)
    encoded = jwt.encode(
        claims(),
        "e" * 32,
        algorithm="HS256",
        headers={"kid": KEY_ID},
    )

    assert_rejected(subject, encoded)
    assert resolver.calls == []


@pytest.mark.parametrize(
    "updates",
    [
        {"iss": "https://other.example.test/tenant"},
        {"aud": "other-api"},
    ],
)
def test_rejects_wrong_issuer_or_audience(
    key_material: KeyMaterial,
    updates: Mapping[str, object],
) -> None:
    encoded = token(key_material, updates=updates)

    assert_rejected(verifier(key_material), encoded)
    assert "other" not in str(
        pytest.raises(OidcVerificationError, verifier(key_material).verify, encoded).value
    )


def test_rejects_expired_token(key_material: KeyMaterial) -> None:
    now = int(time())
    assert_rejected(
        verifier(key_material),
        token(key_material, updates={"exp": now - 1, "iat": now - 120}),
    )


@pytest.mark.parametrize("future_claim", ["iat", "nbf"])
def test_rejects_not_yet_valid_token(
    key_material: KeyMaterial,
    future_claim: str,
) -> None:
    now = int(time())
    assert_rejected(
        verifier(key_material),
        token(key_material, updates={future_claim: now + 60, "exp": now + 300}),
    )


@pytest.mark.parametrize("missing", ["exp", "iat", "sub", "roles", "principal_kind"])
def test_rejects_missing_required_claim(key_material: KeyMaterial, missing: str) -> None:
    assert_rejected(verifier(key_material), token(key_material, remove=(missing,)))


@pytest.mark.parametrize(
    "roles",
    [
        [],
        "pipeline_td",
        ["pipeline_td", 7],
        ["pipeline_td", "pipeline_td"],
        ["role with spaces"],
        ["Uppercase"],
        ["r" * 65],
    ],
)
def test_rejects_invalid_roles(key_material: KeyMaterial, roles: object) -> None:
    assert_rejected(verifier(key_material), token(key_material, updates={"roles": roles}))


@pytest.mark.parametrize("subject", [None, 7, "", " operator-1", "s" * 257])
def test_rejects_invalid_subject(key_material: KeyMaterial, subject: object) -> None:
    assert_rejected(verifier(key_material), token(key_material, updates={"sub": subject}))


@pytest.mark.parametrize("principal_kind", [None, "model", "operator", 7])
def test_rejects_untrusted_principal_kind(
    key_material: KeyMaterial, principal_kind: object
) -> None:
    assert_rejected(
        verifier(key_material),
        token(key_material, updates={"principal_kind": principal_kind}),
    )


def test_accepts_service_principal_kind(key_material: KeyMaterial) -> None:
    principal = verifier(key_material).verify(
        token(key_material, updates={"principal_kind": "service"})
    )
    assert principal.principal_kind == "service"


def test_rejects_missing_or_unknown_key_identifier(key_material: KeyMaterial) -> None:
    subject = verifier(key_material)

    assert_rejected(subject, token(key_material, kid=None))
    assert_rejected(subject, token(key_material, kid="unknown-key"))


def test_rejects_oversized_token_before_key_resolution(key_material: KeyMaterial) -> None:
    resolver = LocalResolver({KEY_ID: key_material.public_jwk})
    subject = OidcTokenVerifier(issuer=ISSUER, audience=AUDIENCE, resolver=resolver)
    encoded = token(key_material, updates={"padding": "x" * 20_000})

    assert len(encoded.encode("ascii")) > 16_384
    assert_rejected(subject, encoded)
    assert resolver.calls == []


def test_rejects_excessive_claim_count(key_material: KeyMaterial) -> None:
    additions = {f"claim_{index}": index for index in range(64)}
    assert_rejected(verifier(key_material), token(key_material, updates=additions))


@pytest.mark.parametrize(
    "issuer",
    ["http://identity.example.test", "https://user@example.test", "https://example.test/#x"],
)
def test_requires_https_oidc_issuer(key_material: KeyMaterial, issuer: str) -> None:
    with pytest.raises(ValueError, match="issuer must be a bounded HTTPS URL"):
        OidcTokenVerifier(
            issuer=issuer,
            audience=AUDIENCE,
            resolver=LocalResolver({KEY_ID: key_material.public_jwk}),
        )


@pytest.mark.parametrize(
    "jwks_uri",
    ["http://identity.example.test/jwks", "https://user@example.test/jwks"],
)
def test_requires_https_jwks_uri(jwks_uri: str) -> None:
    with pytest.raises(ValueError, match="jwks_uri must be a bounded HTTPS URL"):
        HttpsJwksResolver(jwks_uri)


@pytest.mark.parametrize("leeway", [-1, 121, float("inf")])
def test_rejects_unbounded_leeway(key_material: KeyMaterial, leeway: float) -> None:
    with pytest.raises(ValueError, match="leeway_seconds is outside its supported range"):
        verifier(key_material, leeway_seconds=leeway)
