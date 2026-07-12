"""Schema version constants and the policy for bumping them.

A bundle signed under any 1.x schema must keep verifying forever, and data
captured under an old version can never be re-read with different field
semantics. The schema therefore evolves under a strict semver policy on
``SCHEMA_VERSION``:

- **PATCH** (``x.y.Z``): documentation changes and code-only fixes that leave
  field semantics and the canonicalization rules unchanged. No field is added,
  removed, renamed, retyped, or given a new meaning, and the canonical bytes of
  any given logical bundle are identical before and after. A hardening fix in a
  verify error path is a PATCH; so is a docs-only release.
- **MINOR** (``x.Y.0``): *additive* changes only: a new **optional** field
  (with a default) or a new enum member. Existing bundles remain readable
  unchanged (backward read-compatibility is mandatory). A consumer on an older
  minor may not recognise the new field, which is why verification of stored
  bundles goes through the raw-bytes path (``verify_bundle_json``): it
  reproduces the signed bytes regardless of the reader's schema version.
- **MAJOR** (``X.0.0``): a *breaking* change: removing, renaming, or retyping a
  field that existing bundles use, or changing canonicalization. Requires a
  written migration. Major bumps are rare and deliberate; the schema captures
  wide on day one precisely so later needs land as minors, not majors.

Every bundle records its ``schema_version`` so a verifier can select the
matching canonicalization and field set. The canonicalization rules themselves
are frozen in ``docs/adr/0002-evidence-schema-freeze.md``.
"""

from __future__ import annotations

#: The frozen schema version. Bump per the policy in this module's docstring.
SCHEMA_VERSION: str = "1.2.1"

#: The canonicalization scheme identifier embedded in every signature. Changing this
#: string is a MAJOR change (it alters the signable bytes for all bundles).
CANONICALIZATION_SCHEME: str = "RFC8785"

#: The signing algorithm identifier embedded in every signature.
SIGNATURE_ALGORITHM: str = "ECDSA-P384-SHA384"

__all__ = ["SCHEMA_VERSION", "CANONICALIZATION_SCHEME", "SIGNATURE_ALGORITHM"]
