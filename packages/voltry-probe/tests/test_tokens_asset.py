"""Drift guard: the vendored tokens.css must match the brand source tokens.json.

The probe inlines a vendored copy of the generated tokens CSS for offline rendering.
This test asserts every CSS-emitted brand token appears in that vendored asset, and that
color/dimension values are byte-equal, so it can never silently drift from the single
source. It mirrors the Style Dictionary build rules in ``packages/tokens/transform.mjs``:
the ``color``/``dimension`` category wrapper is stripped from var names, ``{a.b.c}``
references resolve to their target values, shadow/border/fontFamily compose to CSS
strings, and composite typography / bare-number tokens are not emitted to CSS at all.
Runs only inside the monorepo (where tokens.json is present); skipped for a pip-installed
probe.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from pathlib import Path

import pytest

_TOKENS_JSON = Path(__file__).resolve().parents[2] / "tokens" / "tokens.json"

# Mirrors CATEGORY_WRAPPERS in packages/tokens/transform.mjs.
_CATEGORY_WRAPPERS = {"color", "dimension"}


def _vendored_css() -> str:
    return (resources.files("voltry_probe.render") / "assets" / "tokens.css").read_text(
        encoding="utf-8"
    )


def _flatten(
    node: dict, path: list[str] | None = None, inherited_type: str | None = None
) -> list[tuple[list[str], str | None, object]]:
    """DTCG leaves as (path, effective $type, $value); a group's $type inherits downward."""
    path = path or []
    group_type = node.get("$type", inherited_type)
    out: list[tuple[list[str], str | None, object]] = []
    for key, val in node.items():
        if key.startswith("$"):
            continue
        if isinstance(val, dict) and "$value" in val:
            out.append(([*path, key], val.get("$type", group_type), val["$value"]))
        elif isinstance(val, dict):
            out.extend(_flatten(val, [*path, key], group_type))
    return out


def _resolve(value: object, root: dict) -> object:
    """Resolve ``{a.b.c}`` references (possibly chained) to the target leaf's $value."""
    while isinstance(value, str) and value.startswith("{") and value.endswith("}"):
        node: object = root
        for seg in value[1:-1].split("."):
            node = node[seg]  # type: ignore[index]
        value = node["$value"]  # type: ignore[index]
    return value


def _compose(token_type: str | None, value: object) -> str | None:
    """The CSS string for a token, or None when the token is not emitted to CSS.

    Mirrors composeValue in transform.mjs: scalar strings pass through; shadow/border/
    fontFamily compose; everything else (composite typography, bare numbers) is skipped.
    """
    if isinstance(value, str):
        return value
    if token_type == "shadow":
        layers = value if isinstance(value, list) else [value]
        return ", ".join(
            (
                f"{'inset ' if layer.get('inset') else ''}{layer['offsetX']} "
                f"{layer['offsetY']} {layer['blur']} {layer.get('spread', '0px')} "
                f"{layer['color']}"
            ).strip()
            for layer in layers
        )
    if token_type == "border":
        return f"{value['width']} {value['style']} {value['color']}"  # type: ignore[index]
    if token_type == "fontFamily":
        return ", ".join(value) if isinstance(value, list) else str(value)
    return None


def _var_name(path: list[str]) -> str:
    segs = path[1:] if path[0] in _CATEGORY_WRAPPERS else path
    return "--" + "-".join(segs)


def _parse_css(css: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in css.splitlines():
        m = re.match(r"\s*(--[\w-]+):\s*(.+?);(?:\s*/\*.*\*/)?\s*$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


@pytest.mark.skipif(
    not _TOKENS_JSON.exists(), reason="brand tokens.json only present in the monorepo"
)
def test_vendored_tokens_match_brand_source():
    source = json.loads(_TOKENS_JSON.read_text(encoding="utf-8"))
    css = _parse_css(_vendored_css())
    checked = 0
    for path, token_type, raw_value in _flatten(source):
        resolved = _resolve(raw_value, source)
        emitted = _compose(token_type, resolved)
        if emitted is None:
            continue  # not a CSS-emitted token (composite typography, bare number)
        name = _var_name(path)
        assert name in css, f"vendored tokens.css missing {name} (regenerate the asset)"
        if token_type in ("color", "dimension"):
            assert css[name] == emitted, f"vendored {name} drifted from tokens.json"
        checked += 1
    # Guard the guard: a broken flatten must not silently pass on zero tokens.
    assert checked > 80, f"only {checked} tokens checked; flatten/emission rules broken?"
