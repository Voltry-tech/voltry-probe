"""Canonicalization byte-stability. Signed bundles must re-verify years from now,
which only works if canonicalization never drifts.

Covers: determinism within a process, across a fresh process (no hidden in-memory
state), key-order independence, signature exclusion, a golden vector pinned by
hash, the safe-integer error path, and a hypothesis property test over varied bundles.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st

import evidence_schema as es
from evidence_schema import (
    AgentInfo,
    Attestation,
    AttestationVerdict,
    DeterministicGates,
    EccCounters,
    EvidenceBundle,
    GateResult,
    History,
    IdentityBlock,
    IdentityScheme,
    MeasuredBlock,
    PageRetirement,
    ProvenanceBlock,
    RawPayload,
    RawReads,
    RunMode,
    SpareRows,
    Tier,
    XidEvent,
)
from evidence_schema.canonicalize import CanonicalizationError, canonical_bytes
from evidence_schema.samples import worked_example_a_bundle

# Golden hash of the canonical bytes of the worked-example bundle. If canonicalization
# ever changes, this fails loudly, which is exactly what we want for a frozen contract.
# Updated at 1.2.0: the worked example gained attestation challenge/freshness fields
# (additive minor change; the canonicalization RULES are unchanged, the example's
# content grew). Old signed bundles still verify via canonical_bytes_from_payload.
# Updated at 1.2.1: the example's schema_version string changed and its attestation
# became challenge=None / freshness NOT_ASSESSED (the old sample claimed a freshness
# PASS that its placeholder report could never substantiate). Content change only;
# the canonicalization rules are still untouched.
# Updated at 1.2.2: only the embedded schema_version string moved (1.2.1 -> 1.2.2);
# the canonicalization rules are unchanged and all prior signed bundles still verify.
GOLDEN_SHA256 = "a85c6e4a33b03075f97b305bf2d4a0046730810d6feedbb14dc3efa474f5c766"

# --- hypothesis strategy: varied but always-valid bundles (this file is the only user) ---
_safe_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=24)
_count = st.integers(min_value=0, max_value=1_000_000)
_utc_dt = st.datetimes(
    min_value=datetime(2000, 1, 1), max_value=datetime(2100, 1, 1), timezones=st.just(timezone.utc)
)
_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.floats(allow_nan=False, allow_infinity=False, width=64),
    _safe_text,
)


@st.composite
def bundles(draw: st.DrawFn) -> EvidenceBundle:
    """Generate a varied (but always valid) EvidenceBundle."""
    xids = draw(
        st.lists(
            st.builds(
                XidEvent,
                xid=st.integers(min_value=0, max_value=999),
                count=st.integers(min_value=0, max_value=1000),
                category=_safe_text.filter(lambda s: len(s) >= 1) | st.just("uncategorized"),
                critical=st.booleans(),
            ),
            max_size=3,
        )
    )
    extensions = draw(st.dictionaries(_safe_text, _json_scalar, max_size=4))
    payloads = draw(
        st.lists(
            st.builds(
                RawPayload,
                source=st.sampled_from(["nvml", "dcgm", "redfish", "attestation"]),
                key=_safe_text | st.just("payload"),
                content=_safe_text,
            ),
            max_size=3,
        )
    )
    remaining = draw(st.integers(min_value=0, max_value=512))
    return EvidenceBundle(
        created_at=draw(_utc_dt),
        agent=AgentInfo(
            name=draw(_safe_text) or "voltry-probe",
            version=draw(_safe_text) or "0.0.0",
            run_mode=draw(st.sampled_from(list(RunMode))),
        ),
        methodology_version_hash=draw(_safe_text) or "hash",
        identity=IdentityBlock(
            device_part=draw(_safe_text) or "H100-SXM5",
            serial=draw(_safe_text) or "SN",
            ecc384_id=draw(_safe_text) or "ecc384",
            attestation=Attestation(
                scheme=draw(st.sampled_from(list(IdentityScheme))),
                verdict=draw(st.sampled_from(list(AttestationVerdict))),
                root_reachability=draw(st.booleans()),
            ),
            reflash_detected=draw(st.booleans()),
            identity_scheme=draw(st.sampled_from(list(IdentityScheme))),
            authenticity_confidence=draw(st.floats(min_value=0.0, max_value=1.0, allow_nan=False)),
            gates=DeterministicGates(
                authenticity=draw(st.sampled_from(list(GateResult))),
                firmware_vbios=draw(st.sampled_from(list(GateResult))),
            ),
        ),
        measured=MeasuredBlock(
            ecc=EccCounters(volatile_correctable=draw(_count), aggregate_correctable=draw(_count)),
            xid=xids,
            pages=PageRetirement(remapped=draw(_count)),
            spare_rows=SpareRows(used=512 - remaining, remaining=remaining, cap=512),
            extensions=extensions,
        ),
        raw_reads=RawReads(payloads=payloads),
        provenance=ProvenanceBlock(
            tier=draw(st.sampled_from(list(Tier))),
            history=draw(st.sampled_from(list(History))),
            chain_gaps=draw(st.booleans()),
            exposure_assessed=draw(st.booleans()),
        ),
    )


def test_canonical_is_deterministic(sample_bundle):
    assert canonical_bytes(sample_bundle) == canonical_bytes(sample_bundle)


def test_canonical_compact_and_sorted(sample_bundle):
    import rfc8785

    from evidence_schema.canonicalize import canonical_json

    # RFC 8785 produces no insignificant whitespace and sorts keys (controlled input,
    # so no opaque string values can carry incidental ", "/": ").
    assert rfc8785.dumps({"b": 1, "a": [1, 2], "c": "x"}) == b'{"a":[1,2],"b":1,"c":"x"}'
    # Real bundle: top-level keys sorted, so 'agent' first, 'schema_version' last.
    raw = canonical_bytes(sample_bundle)
    assert raw.startswith(b'{"agent":')
    assert raw.rstrip().endswith(b'"schema_version":"1.2.2"}')
    # canonical_json is the UTF-8 decode of the same bytes.
    assert canonical_json(sample_bundle) == raw.decode("utf-8")


def test_signature_excluded_from_canonical(sample_bundle, keypair):
    """Signing does not change the canonical bytes (signature is excluded)."""
    signed = es.sign_bundle(sample_bundle, keypair)
    assert canonical_bytes(signed) == canonical_bytes(sample_bundle)


def test_key_order_independence():
    """Insertion order of an extensions dict must not change canonical bytes (keys are sorted)."""
    a = worked_example_a_bundle()
    b = worked_example_a_bundle()
    a.measured.extensions = {"alpha": 1, "beta": 2, "gamma": 3}
    b.measured.extensions = {"gamma": 3, "beta": 2, "alpha": 1}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_cross_process_stability():
    """Identical bytes across a fresh process (no shared in-memory state)."""
    in_process = hashlib.sha256(canonical_bytes(worked_example_a_bundle())).hexdigest()
    script = (
        "import hashlib;"
        "from evidence_schema.canonicalize import canonical_bytes;"
        "from evidence_schema.samples import worked_example_a_bundle;"
        "print(hashlib.sha256(canonical_bytes(worked_example_a_bundle())).hexdigest())"
    )
    result = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )
    other_process = result.stdout.strip()
    assert other_process == in_process


def test_golden_vector():
    """Pin the canonical bytes of Worked Example A by hash (drift detector)."""
    digest = hashlib.sha256(canonical_bytes(worked_example_a_bundle())).hexdigest()
    assert (
        digest == GOLDEN_SHA256
    ), f"canonicalization drifted; update GOLDEN_SHA256 if intentional. got {digest}"


def test_large_extension_integer_raises():
    """An out-of-domain integer that slipped into extensions surfaces a typed error."""
    b = worked_example_a_bundle()
    b.measured.extensions = {"too_big": 2**60}  # > 2**53, bypasses the typed Count bound
    try:
        canonical_bytes(b)
        raised = False
    except CanonicalizationError:
        raised = True
    assert raised, "expected CanonicalizationError for an out-of-domain integer"


@settings(max_examples=150)
@given(bundle=bundles())
def test_property_byte_stability(bundle):
    """For any generated bundle: canonicalization is deterministic and round-trip stable."""
    once = canonical_bytes(bundle)
    twice = canonical_bytes(bundle)
    assert once == twice
    # Rebuild the same logical bundle from its JSON projection: identical bytes.
    rebuilt = es.EvidenceBundle.model_validate(bundle.model_dump(mode="json"))
    assert canonical_bytes(rebuilt) == once
