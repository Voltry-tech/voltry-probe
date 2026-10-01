"""Offline proof that you hold a signing key, for registering it with a Voltry organization.

An organization owner or admin starts "Add signing key" in the Voltry console, which shows a
single-use registration challenge. ``voltry key register`` signs that challenge with the
operator's P-384 signing key, on the operator's own machine, and prints a proof to paste
back into the console. Nothing here touches the network or the device.

Wire formats (the platform's, reproduced exactly):

* challenge: ``vsc1.<org_id>.<nonce_b64url>``, where ``org_id`` is the organization's UUID
  in canonical lowercase form and the nonce is exactly 32 bytes of unpadded base64url;
* proof: ``vsr1.<spki_b64url>.<signature_b64url>``, unpadded base64url throughout.

The signed transcript binds a lane tag, the nonce, the organization and the key itself::

    lp("voltry.org.signer-pop/v1") || lp(nonce) || lp(org_id) || lp(spki_der)

where ``lp(x)`` is ``x`` prefixed by its 4-byte big-endian byte length, ``org_id`` is the
canonical UUID string as UTF-8, and ``spki_der`` is the key's canonical DER
SubjectPublicKeyInfo (uncompressed point, named curve). The signature is ECDSA P-384 over
SHA-384 in DER form (an ASN.1 SEQUENCE of r and s); the platform refuses a raw ``r || s``
signature as ``possession_not_proven``.

Why this is reimplemented rather than imported: the probe cannot depend on the platform
service, and the evidence schema is frozen. The shared golden vector in
``tests/fixtures/org_signer_pop_vector.json`` is asserted by this package's tests and by the
platform's, so the two implementations cannot drift apart silently.

The key fingerprint is ``sha384:`` plus the hex SHA-384 of the canonical SPKI DER: the same
value the console lists for a registered key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

#: Domain-separation tag of the org signing-key lane. Distinct from every other Voltry
#: possession ceremony, so a proof made here can never be replayed on another lane.
SIGNER_POP_TAG = "voltry.org.signer-pop/v1"

#: Wire prefixes of the challenge the console shows and the proof this tool prints.
CHALLENGE_PREFIX = "vsc1"
PROOF_PREFIX = "vsr1"

#: Registration nonces are exactly 32 bytes.
NONCE_BYTES = 32

_B64URL_RE = re.compile(r"[A-Za-z0-9_-]+")


class ChallengeError(ValueError):
    """The text is not a well-formed registration challenge. Nothing was signed."""


class OrgMismatchError(ValueError):
    """The organization the operator confirmed is not the one in the challenge. Nothing
    was signed."""


@dataclass(frozen=True)
class Registration:
    """What ``sign_registration`` returns: who the key is being registered to, and the proof."""

    #: The organization named inside the challenge. The operator must confirm it.
    org_id: UUID
    #: ``sha384:`` fingerprint of the key being registered.
    fingerprint: str
    #: ``vsr1.<spki_b64url>.<signature_b64url>``, to paste into the console.
    proof: str


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode_strict(text: str) -> bytes:
    """Decode unpadded base64url, accepting only its one canonical spelling."""
    if not _B64URL_RE.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("not unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError("not unpadded base64url") from exc
    if _b64url_encode(raw) != text:
        raise ValueError("not the canonical base64url spelling")
    return raw


def _lp(component: bytes) -> bytes:
    return len(component).to_bytes(4, "big") + component


def parse_challenge(challenge: str) -> tuple[UUID, bytes]:
    """Split ``vsc1.<org_id>.<nonce_b64url>`` into (org_id, nonce).

    Raises ``ChallengeError`` for anything the platform would not accept: a wrong prefix or
    part count, a non-canonical org id, a nonce that is not unpadded base64url or not
    exactly 32 bytes.
    """
    parts = challenge.strip().split(".")
    if len(parts) != 3 or parts[0] != CHALLENGE_PREFIX:
        raise ChallengeError(
            f"a registration challenge looks like {CHALLENGE_PREFIX}.<org id>.<nonce>; "
            "copy it again from the add-key page in the Voltry console"
        )
    try:
        org_id = UUID(parts[1])
        nonce = _b64url_decode_strict(parts[2])
    except ValueError as exc:
        raise ChallengeError(
            "the registration challenge is damaged; copy it again from the Voltry console"
        ) from exc
    if str(org_id) != parts[1] or len(nonce) != NONCE_BYTES:
        raise ChallengeError(
            "the registration challenge is damaged; copy it again from the Voltry console"
        )
    return org_id, nonce


def canonical_spki_der(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """The key's canonical DER SubjectPublicKeyInfo: the only encoding the platform accepts."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def fingerprint(spki_der: bytes) -> str:
    """``sha384:`` plus the hex SHA-384 of the SPKI DER (the console's key fingerprint)."""
    return "sha384:" + hashlib.sha384(spki_der).hexdigest()


def transcript(*, nonce: bytes, org_id: UUID, spki_der: bytes) -> bytes:
    """The exact bytes signed to prove possession. Raises ``ValueError`` on a wrong nonce size."""
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"the registration nonce is exactly {NONCE_BYTES} bytes, got {len(nonce)}")
    return (
        _lp(SIGNER_POP_TAG.encode("utf-8"))
        + _lp(nonce)
        + _lp(str(org_id).encode("utf-8"))
        + _lp(spki_der)
    )


def format_proof(spki_der: bytes, signature_der: bytes) -> str:
    """``vsr1.<spki_b64url>.<signature_b64url>``."""
    return f"{PROOF_PREFIX}.{_b64url_encode(spki_der)}.{_b64url_encode(signature_der)}"


def sign_registration(
    private_key: ec.EllipticCurvePrivateKey, challenge: str, *, confirmed_org_id: UUID
) -> Registration:
    """Sign a registration challenge with ``private_key`` and return the proof.

    ``confirmed_org_id`` is the organization the operator confirmed, and it must equal the
    one inside the challenge or nothing is signed (``OrgMismatchError``). A key registers to
    one organization, once, ever, so signing a challenge someone else minted (a phished
    one) would bind the key to their organization for good; making the confirmation an
    argument means no caller can sign without having asked. Raises ``ChallengeError`` for
    a malformed challenge and ``ValueError`` for a key that is not on P-384.
    """
    if not isinstance(private_key.curve, ec.SECP384R1):
        raise ValueError(
            f"the signing key must be on P-384 (secp384r1), got {private_key.curve.name}"
        )
    org_id, nonce = parse_challenge(challenge)
    if confirmed_org_id != org_id:
        raise OrgMismatchError(
            f"the confirmed organization {confirmed_org_id} is not the organization in this "
            f"challenge ({org_id}); nothing was signed"
        )
    spki_der = canonical_spki_der(private_key.public_key())
    message = transcript(nonce=nonce, org_id=org_id, spki_der=spki_der)
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA384()))  # DER-encoded
    return Registration(
        org_id=org_id, fingerprint=fingerprint(spki_der), proof=format_proof(spki_der, signature)
    )


__all__ = [
    "CHALLENGE_PREFIX",
    "NONCE_BYTES",
    "PROOF_PREFIX",
    "SIGNER_POP_TAG",
    "ChallengeError",
    "OrgMismatchError",
    "Registration",
    "canonical_spki_der",
    "fingerprint",
    "format_proof",
    "parse_challenge",
    "sign_registration",
    "transcript",
]
