"""Render an EvidenceBundle to a self-contained, offline HTML certificate.

The output is one HTML string with everything inlined: the generated brand tokens CSS
plus the cert layout, no external stylesheet, script, font, or image fetch. That is what
lets the file open air-gapped; the offline test blocks sockets at runtime to prove it.

Layout is the four-block certificate (deterministic gates, measured condition, modeled
fields, provenance and coverage). Blocks 1-2 carry facts, Block 3 carries estimates, and
the two get distinct CSS treatments so a modeled band can never be mistaken for a
measured number. Until the modeling engine ships, Block 3 renders a pending band
placeholder rather than any invented value. "EXPOSURE ASSESSED: NO" is a flagged
standalone element, not a buried table row, and no field states or implies a price
(tests/test_render.py pins all of this).

The dark luminous styles (``surface.*`` / ``luminous.*``) are certificate-only; the
paper UI never uses them.
"""

from __future__ import annotations

import html
from importlib import resources

from evidence_schema import (
    AttestationVerdict,
    DutyBlock,
    EvidenceBundle,
    GateResult,
    History,
    MeasuredBlock,
)

_GLYPH = {GateResult.PASS: "PASS", GateResult.FAIL: "FAIL", GateResult.NOT_ASSESSED: "-"}
_GATE_CLASS = {
    GateResult.PASS: "row__v--pass",
    GateResult.FAIL: "row__v--fail",
    GateResult.NOT_ASSESSED: "row__v--na",
}


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _asset(name: str) -> str:
    return (resources.files("voltry_probe.render") / "assets" / name).read_text(encoding="utf-8")


def _styles() -> str:
    """The inlined stylesheet: generated brand tokens + cert layout (offline)."""
    return _asset("tokens.css") + "\n" + _asset("certificate.css")


def _row(key: str, value: str, value_class: str = "") -> str:
    cls = f"row__v {value_class}".strip()
    return (
        f'<div class="row"><span class="row__k">{_esc(key)}</span>'
        f'<span class="{cls}">{_esc(value)}</span></div>'
    )


def _warn_row(key: str, value: str) -> str:
    """A high-visibility row for reported failure / pending states. Styled at the row
    level (``row--warn``), not just the value, so it stands out from the fact rows and
    cannot be read as a clean number."""
    return (
        f'<div class="row row--warn"><span class="row__k">{_esc(key)}</span>'
        f'<span class="row__v row__v--warn">{_esc(value)}</span></div>'
    )


def _gate_row(key: str, result: GateResult) -> str:
    return _row(key, _GLYPH[result], _GATE_CLASS[result])


def _section(block_class: str, heading: str, inner: str) -> str:
    return (
        f'<section class="block {block_class}"><h2 class="block__h">{heading}</h2>{inner}</section>'
    )


def _block_gates(bundle: EvidenceBundle) -> str:
    g = bundle.identity.gates
    rows = (
        _gate_row("Authenticity", g.authenticity)
        + _gate_row("Firmware / VBIOS", g.firmware_vbios)
        + _gate_row("Functional burn-in", g.functional_burnin)
        + _gate_row("SDC functional test", g.sdc_functional)
        + _gate_row("Data sanitization (2883-2022)", g.data_sanitization)
    )
    return _section("block--measured", "1 · Deterministic gates (measured)", rows)


def _remap_rows(measured: MeasuredBlock) -> str:
    """Row-remap accounting from InfoROM.

    The margin is reported as an InfoROM-derived count of consumed remaps against the
    fixed cap (used / cap), not as literal physical spare-row headroom: NVIDIA documents
    these as InfoROM remap counters, not a direct count of surviving physical rows.
    Correctable and uncorrectable remaps are shown separately (collapsing them into one
    number invites an unwarranted read), and any reported failure or pending state
    surfaces as a high-visibility row regardless of how clean the margin looks."""
    sr = measured.spare_rows
    rows = ""
    # Reported failure and pending states lead, so they cannot be lost under a clean margin.
    if sr.failure_occurred:
        rows += _warn_row("Row-remap failure", "REPORTED (InfoROM failureOccurred)")
    if sr.pending > 0:
        rows += _warn_row("Row remap pending", str(sr.pending))
    rows += _row("Row-remap margin (InfoROM)", f"{sr.used} used / {sr.cap} cap", "gauge")

    def _split(v: int | None) -> str:
        return "not separable" if v is None else str(v)

    rows += _row("  remaps, correctable", _split(sr.correctable_remaps))
    rows += _row("  remaps, uncorrectable", _split(sr.uncorrectable_remaps))
    return rows


def _block_measured(bundle: EvidenceBundle) -> str:
    m = bundle.measured
    xid_critical = sum(e.count for e in m.xid if e.critical)
    stable = not (
        m.stability.thermal_throttle_active
        or m.stability.power_throttle_active
        or m.stability.hw_slowdown_active
    )
    pages_pending = (
        _warn_row("Pages pending retirement", str(m.pages.pending_retirement))
        if m.pages.pending_retirement > 0
        else ""
    )
    rows = (
        _row("Uncorrectable ECC events", str(m.ecc.aggregate_uncorrectable))
        + (
            _row("Xid critical events", str(xid_critical))
            if m.xid or "xid_events_source" in m.extensions
            else _row("Xid critical events", "not read", "row__v--na")
        )
        + _row(
            "Retired / remapped pages", f"{m.pages.retired} retired / {m.pages.remapped} remapped"
        )
        + pages_pending
        + _remap_rows(m)
        + _row(
            "Throttle / clock / power", "stable, within spec" if stable else "throttling observed"
        )
        + _duty_rows(m.duty)
    )
    return _section("block--measured", "2 · Measured condition (facts)", rows)


_DUTY_BASIS = {
    "monitor_continuous": "continuous monitoring",
    "registry_accumulated": "registry deltas across scans",
}


def _duty_rows(duty: DutyBlock | None) -> str:
    """The odometer rows. Duty accumulates across scans or continuous monitoring; a
    single cold read cannot measure it, so an absent DutyBlock renders as
    not-accumulated rather than as zero hours (zero would read as a pristine board)."""
    if duty is None:
        return _row("Lifetime duty (odometer)", "not accumulated (single read)", "row__v--na")

    def num(v: float | int | None, unit: str = "") -> str:
        return "-" if v is None else f"{v:,.0f}{unit}"

    basis = _DUTY_BASIS.get(duty.basis or "", duty.basis or "-")
    since = f" since {duty.since.date().isoformat()}" if duty.since else ""
    return (
        _row("GPU-hours (lifetime)", num(duty.gpu_hours_total))
        + _row("Thermal cycles (lifetime)", num(duty.thermal_cycles_total))
        + _row("Sustained high-power (>95% TDP)", num(duty.sustained_high_power_hours, " h"))
        + _row("Energy through board", num(duty.energy_kwh_total, " kWh"))
        + _row("Duty basis", f"{basis}{since}")
    )


def _block_modeled(bundle: EvidenceBundle) -> str:
    """Block 3: pending until the modeling engine ships. No calibration snapshot means
    no estimates exist, so the block explains that and renders a placeholder band."""
    if bundle.calibration_snapshot_id is None:
        inner = (
            '<p class="modeled-pending">Modeled fields (memory / hardware / thermal wear '
            "indices and the Modeled Wear Trajectory) are computed after calibration and are "
            "always reported as a <strong>band with a stated coverage</strong>, never a single "
            "score. Not yet computed for this single-read certificate.</p>"
            '<span class="modeled-band">estimate band: pending · nominal coverage: pending</span>'
        )
    else:  # pragma: no cover - modeled output; not produced until the modeling engine ships
        inner = '<p class="modeled-pending">Modeled fields present; see banded estimates.</p>'
    return _section("block--modeled", "3 · Modeled fields (estimates, read with the band)", inner)


def _block_provenance(bundle: EvidenceBundle) -> str:
    p = bundle.provenance
    rows = (
        _row("Tier", p.tier.value)
        + _row("History", "BORN-ON" if p.history is History.BORN_ON else "RECONSTRUCTED")
        + _row("Chain gaps", "YES" if p.chain_gaps else "NO")
    )
    if p.exposure_assessed:
        exposure = (
            '<div class="exposure exposure--yes"><span class="exposure__label">EXPOSURE ASSESSED'
            "</span><span>YES: power-chain history assessed</span></div>"
        )
    else:
        exposure = (
            '<div class="exposure exposure--no"><span class="exposure__label">EXPOSURE ASSESSED'
            "</span><span>NO ✳ power-chain history NOT assessed</span></div>"
        )
    return _section("block--provenance", "4 · Provenance &amp; coverage", rows + exposure)


def render_certificate(
    bundle: EvidenceBundle, *, verified: bool, verify_url: str | None = None
) -> str:
    """Render ``bundle`` to a self-contained, offline HTML certificate string.

    ``verified`` is the caller's result of cryptographically verifying the bundle's
    signature (see ``evidence_schema.verify_bundle``). It is required, never defaulted:
    a certificate must never present itself as authoritative unless the signature was
    actually checked. When ``verified`` is False the certificate carries a prominent
    UNVERIFIED banner and drops every "verified" claim; the rendered HTML is then a
    view, not proof. Note the two axes are distinct: ``verified`` gates whether the
    certificate is authoritative at all, while the "bound & verified" wording on the
    identity line additionally requires a passing hardware-attestation verdict.
    """
    ident = bundle.identity
    bound = (
        "bound & verified"
        if verified and ident.attestation.verdict is AttestationVerdict.VERIFIED
        else "bound"
    )
    methodology_short = bundle.methodology_version_hash[:8]
    calib = bundle.calibration_snapshot_id or "-"
    tier_word = bundle.provenance.tier.value
    verify_text = verify_url or f"voltry verify · {bundle.bundle_id}"

    head = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>Voltry Certificate: {_esc(ident.device_part)}</title>"
        f"<style>{_styles()}</style></head>"
    )
    identity_html = (
        f'<div class="cert__identity">Asset identity: {_esc(ident.device_part)}<br>'
        f"device-unique ECC-384 id · {_esc(ident.ecc384_id[:24])}... · {_esc(bound)}</div>"
    )
    meta_html = (
        f'<div class="cert__meta">Tier: {_esc(tier_word)} · '
        f"Methodology v-hash {_esc(methodology_short)} · calib {_esc(calib)}</div>"
    )
    # Plain text, deliberately: an earlier revision drew a decorative QR-looking SVG here
    # that encoded nothing, which is exactly the kind of implied-but-fake verifiability
    # this certificate exists to avoid. The real QR lives on the platform verify surface.
    verify_html = (
        '<div class="verify">'
        f'<span class="verify__line">bundle {_esc(str(bundle.bundle_id)[:12])}</span>'
        f'<span class="verify__line">{_esc(verify_text)}</span></div>'
    )
    if verified:
        banner = ""
        # Offline verification proves only self-consistency: the bundle is intact and
        # signed by the key embedded in it. It does NOT prove the signer is an authorized
        # Voltry/operator key; that check lives on the platform verify surface. Say so,
        # rather than let "verified" read as third-party proof of authenticity.
        footer = (
            '<div class="footer">Signature self-consistent and replayable from the bundle. '
            "Signer authorization is confirmed at Voltry verify, not offline. Measured facts "
            "are deterministic; modeled fields are banded estimates.</div>"
        )
    else:
        banner = (
            '<div class="cert__unverified" role="alert">UNVERIFIED: the signature on this '
            "bundle was not validated. This is a rendered view, not cryptographic proof. "
            "Verify at the source before relying on it.</div>"
        )
        footer = (
            '<div class="footer">UNVERIFIED rendered view. Confirm the signed evidence '
            "bundle before relying on any field above.</div>"
        )
    body = (
        '<body><main class="cert"><div class="cert__wave"></div><div class="cert__body">'
        + banner
        + '<h1 class="cert__title">Certified by Voltry: Condition &amp; Provenance Record</h1>'
        + identity_html
        + meta_html
        + _block_gates(bundle)
        + _block_measured(bundle)
        + _block_modeled(bundle)
        + _block_provenance(bundle)
        + verify_html
        + footer
        + "</div></main></body></html>"
    )
    return head + body
