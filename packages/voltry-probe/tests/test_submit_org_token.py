"""`voltry submit --org-token-env NAME`: uploading to your organization with an upload token.

The token is a write credential for the organization, so the CLI handles it narrowly:

* it is read from the named environment variable ONLY; no option takes the token itself,
  and a token pasted where the variable NAME goes is refused (and never echoed);
* its shape is checked locally before anything is sent;
* it travels in ``X-Voltry-Upload-Token`` to ``/v1/org/upload`` by default, never in the URL,
  on stdout, or on stderr;
* every existing submit rule (consent, a verifying signature, https) still applies first;
* an ``unregistered_signer`` refusal says how to register the key;
* without the flag, ``voltry submit`` behaves exactly as before.
"""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from typer.testing import CliRunner

from voltry_probe import cli as cli_module
from voltry_probe.cli import (
    DEFAULT_INGEST_URL,
    DEFAULT_ORG_UPLOAD_URL,
    UPLOAD_TOKEN_HEADER,
    app,
)

runner = CliRunner()
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "h100_read.json"

TOKEN = "vot_" + "0123456789abcdef01234567" + "." + "Zm9vYmFyLXNlY3JldC1ub3QtcmVhbC0wMTIzNDU2Nzg5"
ENV = "VOLTRY_UPLOAD_TOKEN"


def _text(result) -> str:
    """All captured text (stdout + stderr), across click versions (the test_cli idiom)."""
    out = result.stdout or ""
    try:
        err = result.stderr or ""
    except (ValueError, RuntimeError):  # stderr not separately captured
        err = ""
    return out + err


def _fake_httpx(status_code: int = 200, body: str = ""):
    """A stand-in httpx module recording post() calls."""
    mod = types.ModuleType("httpx")

    class HTTPError(Exception):
        pass

    class InvalidURL(Exception):  # not an HTTPError, as in httpx
        pass

    calls: list[dict] = []

    def post(url, content=None, headers=None, timeout=None):
        calls.append({"url": url, "content": content, "headers": headers, "timeout": timeout})
        return types.SimpleNamespace(
            status_code=status_code, text=body, json=lambda: json.loads(body)
        )

    mod.HTTPError = HTTPError
    mod.InvalidURL = InvalidURL
    mod.post = post
    mod.calls = calls
    return mod


@pytest.fixture
def bundle_path(tmp_path) -> Path:
    path = tmp_path / "bundle.json"
    result = runner.invoke(
        app, ["scan", "--fixture", str(FIXTURE), "--ephemeral-key", "--out", str(path)]
    )
    assert result.exit_code == 0, _text(result)
    return path


@pytest.fixture
def fake(monkeypatch):
    mod = _fake_httpx()
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _submit(bundle_path: Path, *extra: str, env: dict[str, str] | None = None):
    return runner.invoke(
        app, ["submit", str(bundle_path), "--i-consent-to-submit", *extra], env=env or {}
    )


# ----------------------------------------------------------------- the honest path


def test_the_token_goes_in_its_header_to_the_org_upload_endpoint(bundle_path, fake):
    result = _submit(bundle_path, "--org-token-env", ENV, env={ENV: TOKEN})
    assert result.exit_code == 0, _text(result)
    (call,) = fake.calls
    posted = urlsplit(call["url"])
    assert (posted.scheme, posted.netloc, posted.path, posted.query) == (
        "https",
        "api.voltry.io",
        "/v1/org/upload",
        "consent=true",
    )
    assert DEFAULT_ORG_UPLOAD_URL == "https://api.voltry.io/v1/org/upload"
    assert call["headers"] == {"content-type": "application/json", UPLOAD_TOKEN_HEADER: TOKEN}
    assert UPLOAD_TOKEN_HEADER == "X-Voltry-Upload-Token"
    # The exact signed bytes, as without the flag.
    assert call["content"] == bundle_path.read_text(encoding="utf-8")


def test_an_explicit_url_is_honored_with_the_token(bundle_path, fake):
    result = _submit(
        bundle_path,
        "--org-token-env",
        ENV,
        "--url",
        "https://staging.example/v1/org/upload",
        env={ENV: TOKEN},
    )
    assert result.exit_code == 0, _text(result)
    (call,) = fake.calls
    assert call["url"] == "https://staging.example/v1/org/upload?consent=true"
    assert call["headers"][UPLOAD_TOKEN_HEADER] == TOKEN


def test_surrounding_whitespace_in_the_variable_is_ignored(bundle_path, fake):
    result = _submit(bundle_path, "--org-token-env", ENV, env={ENV: f"  {TOKEN}\n"})
    assert result.exit_code == 0, _text(result)
    assert fake.calls[0]["headers"][UPLOAD_TOKEN_HEADER] == TOKEN


def test_the_token_never_appears_in_output_or_the_url(bundle_path, fake):
    result = _submit(bundle_path, "--org-token-env", ENV, env={ENV: TOKEN})
    assert result.exit_code == 0
    secret = TOKEN.partition(".")[2]
    assert secret not in _text(result)
    assert TOKEN.partition(".")[0] not in _text(result)
    assert secret not in fake.calls[0]["url"]


# ----------------------------------------------------------------- refused locally


@pytest.mark.parametrize("env", [{}, {ENV: ""}, {ENV: "   "}])
def test_an_unset_or_empty_variable_is_refused_before_any_network(bundle_path, fake, env):
    result = _submit(bundle_path, "--org-token-env", ENV, env=env)
    assert result.exit_code == 2
    assert f"{ENV} is not set" in _text(result)
    assert fake.calls == []


@pytest.mark.parametrize(
    "value",
    [
        "not-a-token",
        "vk_" + "0" * 24 + ".partner-key-secret-value",  # a partner key
        "vsr1.abc.def",  # a key-registration proof
        "vot_" + "0" * 23 + ".short-id-value-here",
        "vot_" + "0" * 24 + ".bad secret with spaces",
        "Bearer " + TOKEN,
    ],
)
def test_a_value_that_is_not_an_upload_token_is_refused_and_never_echoed(bundle_path, fake, value):
    result = _submit(bundle_path, "--org-token-env", ENV, env={ENV: value})
    assert result.exit_code == 2
    assert "does not look like a Voltry upload token" in _text(result)
    assert value not in _text(result)
    assert fake.calls == []


@pytest.mark.parametrize("pasted", [TOKEN, TOKEN.partition(".")[0], "vot_anything"])
def test_a_token_passed_in_place_of_the_variable_name_is_refused_and_never_echoed(
    bundle_path, fake, pasted
):
    """The token belongs in the environment. Typed on the command line it may already be in
    shell history, so the CLI refuses, says to rotate it, and never repeats it."""
    result = _submit(bundle_path, "--org-token-env", pasted, env={ENV: TOKEN})
    assert result.exit_code == 2
    text = _text(result)
    assert "not the token itself" in text
    assert "revoke it" in text
    assert pasted not in text
    assert fake.calls == []


@pytest.mark.parametrize("name", ["MY-TOKEN", "1TOKEN", "TOKEN NAME", "", "0123abc.s3cr3t-x"])
def test_an_invalid_variable_name_is_refused_and_never_echoed(bundle_path, fake, name):
    result = _submit(bundle_path, "--org-token-env", name, env={ENV: TOKEN})
    assert result.exit_code == 2
    assert "environment variable name" in _text(result)
    if name:
        assert name not in _text(result)
    assert fake.calls == []


def test_consent_is_still_required_first(bundle_path, fake):
    result = runner.invoke(
        app, ["submit", str(bundle_path), "--org-token-env", ENV], env={ENV: TOKEN}
    )
    assert result.exit_code == 2
    assert "opt-in" in _text(result).lower()
    assert fake.calls == []


@pytest.mark.parametrize(
    "url",
    [
        "https://api.voltry.io/v1/ingest",  # the public route: never where a token goes
        "https://api.voltry.io/v1/org/ingest",
        "https://api.voltry.io/",
        "https://example.test/v1/org/upload-tokens",
        # A trailing slash draws a 307 from the platform instead of an upload.
        "https://api.voltry.io/v1/org/upload/",
        "https://proxy.example/prefix/v1/org/upload/",
    ],
)
def test_the_token_is_only_sent_to_an_org_upload_endpoint(bundle_path, fake, url):
    result = _submit(bundle_path, "--org-token-env", ENV, "--url", url, env={ENV: TOKEN})
    assert result.exit_code == 2
    assert "/v1/org/upload" in _text(result)
    assert fake.calls == []


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8765/v1/org/upload",
        "http://localhost/v1/org/upload",
        "http://[::1]:8000/v1/org/upload",
        "https://proxy.example/prefix/v1/org/upload",
    ],
)
def test_loopback_http_and_prefixed_https_upload_urls_are_allowed(bundle_path, fake, url):
    result = _submit(
        bundle_path,
        "--org-token-env",
        ENV,
        "--url",
        url,
        "--allow-insecure-http",
        env={ENV: TOKEN},
    )
    assert result.exit_code == 0, _text(result)
    assert fake.calls[0]["headers"][UPLOAD_TOKEN_HEADER] == TOKEN


@pytest.mark.parametrize(
    "url",
    [
        "http://staging.example/v1/org/upload",
        "http://localhost.evil.com/v1/org/upload",  # a name that starts with localhost
        "http://localhost@evil.com/v1/org/upload",  # userinfo, the host is evil.com
        "http://127.0.0.1.evil.com/v1/org/upload",
    ],
)
def test_plain_http_to_another_host_never_carries_the_token(bundle_path, fake, url):
    """--allow-insecure-http is for local endpoints; with a token it means this machine."""
    result = _submit(
        bundle_path,
        "--org-token-env",
        ENV,
        "--url",
        url,
        "--allow-insecure-http",
        env={ENV: TOKEN},
    )
    assert result.exit_code == 2
    assert "localhost" in _text(result)
    assert fake.calls == []


MALFORMED_URLS = (
    "https://api.voltry.io:443x/v1/org/upload",  # .port raises ValueError
    "https://[::1/v1/org/upload",  # urlsplit raises ValueError
    "https://api.voltry.io:99999/v1/org/upload",  # port out of range
)


@pytest.mark.parametrize("url", MALFORMED_URLS)
def test_a_malformed_url_is_refused_before_the_token_is_read(bundle_path, fake, monkeypatch, url):
    read: list[str] = []
    real = cli_module._org_upload_token
    monkeypatch.setattr(
        cli_module, "_org_upload_token", lambda name: read.append(name) or real(name)
    )
    result = _submit(bundle_path, "--org-token-env", ENV, "--url", url, env={ENV: TOKEN})
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "not a valid URL" in _text(result)
    assert read == []
    assert fake.calls == []
    assert TOKEN.partition(".")[2] not in _text(result)


@pytest.mark.parametrize(
    "url",
    ["https://api.voltry.io/v1/ingest", "http://evil.example/v1/org/upload"],
)
def test_a_refused_url_is_refused_before_the_token_is_read(bundle_path, fake, monkeypatch, url):
    read: list[str] = []
    monkeypatch.setattr(cli_module, "_org_upload_token", lambda name: read.append(name) or TOKEN)
    result = _submit(
        bundle_path,
        "--org-token-env",
        ENV,
        "--url",
        url,
        "--allow-insecure-http",
        env={ENV: TOKEN},
    )
    assert result.exit_code == 2
    assert read == []


def test_a_malformed_url_without_a_token_is_a_clean_refusal_too(bundle_path, fake):
    result = _submit(bundle_path, "--url", "https://[::1/v1/ingest")
    assert result.exit_code == 2
    assert "not a valid URL" in _text(result)
    assert fake.calls == []


def test_a_host_the_idna_codec_rejects_is_a_clean_failure(bundle_path, monkeypatch):
    """httpx accepts ``https://xn--zz.example/...`` as a URL, then its transport raises
    idna.IDNAError (a ValueError) when it encodes the host. Simulated here with the same
    exception family; a real-httpx run follows."""
    fake = _fake_httpx()

    class IDNAError(UnicodeError):  # idna.IDNAError's own bases
        pass

    def post(url, content=None, headers=None, timeout=None):
        raise IDNAError("Invalid A-label")

    fake.post = post
    monkeypatch.setitem(sys.modules, "httpx", fake)
    result = _submit(
        bundle_path,
        "--org-token-env",
        ENV,
        "--url",
        "https://xn--zz.example/v1/org/upload",
        env={ENV: TOKEN},
    )
    assert result.exit_code == 4
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "upload failed" in _text(result)
    assert TOKEN.partition(".")[2] not in _text(result)


def test_a_bad_idna_host_is_a_clean_failure_with_the_real_client(bundle_path, monkeypatch):
    """The same URL through the real httpx, with every socket path blocked so nothing can
    leave the machine whatever the client does first: a clean exit 4, no traceback."""
    import socket

    pytest.importorskip("httpx")

    def blocked(*args, **kwargs):
        raise OSError("network disabled in this test")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.delitem(sys.modules, "httpx", raising=False)
    result = _submit(
        bundle_path,
        "--org-token-env",
        ENV,
        "--url",
        "https://xn--zz.example/v1/org/upload",
        env={ENV: TOKEN},
    )
    assert result.exit_code == 4, _text(result)
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert TOKEN.partition(".")[2] not in _text(result)


def test_an_invalid_url_raised_by_httpx_is_a_clean_failure(bundle_path, monkeypatch):
    """httpx.InvalidURL is not an httpx.HTTPError; it must not escape as a traceback."""
    fake = _fake_httpx()

    def post(url, content=None, headers=None, timeout=None):
        raise fake.InvalidURL("Invalid non-printable ASCII character in URL")

    fake.post = post
    monkeypatch.setitem(sys.modules, "httpx", fake)
    result = _submit(bundle_path, "--org-token-env", ENV, env={ENV: TOKEN})
    assert result.exit_code == 4
    assert result.exception is None or isinstance(result.exception, SystemExit)
    assert "upload failed" in _text(result)
    assert TOKEN.partition(".")[2] not in _text(result)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
@pytest.mark.parametrize("with_token", [True, False])
def test_a_redirect_is_a_failure_not_a_success(bundle_path, monkeypatch, status, with_token):
    """httpx does not follow redirects, so a 3xx means nothing was recorded: exit 4, and
    never the "submitted" line."""
    fake = _fake_httpx(status_code=status)
    monkeypatch.setitem(sys.modules, "httpx", fake)
    extra = ("--org-token-env", ENV) if with_token else ()
    result = _submit(bundle_path, *extra, env={ENV: TOKEN})
    assert result.exit_code == 4
    assert "redirect" in _text(result)
    assert "submitted" not in _text(result)


@pytest.mark.parametrize("status", [200, 201, 204])
def test_any_2xx_is_success(bundle_path, monkeypatch, status):
    fake = _fake_httpx(status_code=status)
    monkeypatch.setitem(sys.modules, "httpx", fake)
    result = _submit(bundle_path, "--org-token-env", ENV, env={ENV: TOKEN})
    assert result.exit_code == 0, _text(result)
    assert "submitted" in _text(result)


# ----------------------------------------------------------------- tracebacks never show locals


def test_both_typer_apps_never_show_locals_in_a_traceback():
    """Typer before 0.23 printed every frame's locals in a traceback by default, and submit
    holds the token in a local. The floor is typer>=0.23 now, and the app still says so
    explicitly, so neither a future default nor a downgrade can bring locals back."""
    assert cli_module.app.pretty_exceptions_show_locals is False
    assert cli_module.key_app.pretty_exceptions_show_locals is False


#: Brings back Typer's pre-0.23 default (locals shown in tracebacks) for every Typer app
#: built after it runs, so an app that does not set the option explicitly shows locals.
_OLD_TYPER_DEFAULT = """
import typer
_original_init = typer.Typer.__init__
def _old_default_init(self, *args, **kwargs):
    kwargs.setdefault("pretty_exceptions_show_locals", True)
    _original_init(self, *args, **kwargs)
typer.Typer.__init__ = _old_default_init
"""

_FAKE_HTTPX_PRELUDE = """
import sys, types
mod = types.ModuleType("httpx")
class HTTPError(Exception):
    pass
class InvalidURL(Exception):
    pass
def post(url, content=None, headers=None, timeout=None):
    raise RuntimeError("an error nothing anticipated")
mod.HTTPError, mod.InvalidURL, mod.post = HTTPError, InvalidURL, post
sys.modules["httpx"] = mod
"""


def _run_real_cli(args: list[str], *, show_locals: bool | None, fake_httpx: bool) -> tuple:
    """Run the real ``voltry`` entry point in a fresh interpreter, the way a user does, so
    Typer's own traceback handler (not CliRunner's) decides what is printed.

    Typer's old default (show locals) is ALWAYS restored before the CLI is imported, so the
    app's own explicit setting is what stands between a traceback and the token: remove it
    and these tests fail on any Typer version. ``show_locals`` True additionally overrides
    the app's setting after import (the negative control)."""
    import os
    import subprocess

    code = _OLD_TYPER_DEFAULT + (_FAKE_HTTPX_PRELUDE if fake_httpx else "")
    code += "from voltry_probe.cli import app\n"
    if show_locals is not None:
        code += f"app.pretty_exceptions_show_locals = {show_locals!r}\n"
    code += f"import sys\nsys.argv = ['voltry', *{args!r}]\napp()\n"
    env = {k: v for k, v in os.environ.items() if k != "_TYPER_STANDARD_TRACEBACK"}
    env.update({ENV: TOKEN, "COLUMNS": "1000", "NO_COLOR": "1"})
    done = subprocess.run(  # noqa: S603 - the test's own interpreter, fixed code
        [sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60
    )
    return done.returncode, done.stdout + done.stderr


def _submit_args(bundle_path: Path, *extra: str) -> list[str]:
    return ["submit", str(bundle_path), "--i-consent-to-submit", "--org-token-env", ENV, *extra]


@pytest.mark.parametrize("url", MALFORMED_URLS)
def test_malformed_urls_never_print_the_token_even_with_locals_forced_on(bundle_path, url):
    code, output = _run_real_cli(
        _submit_args(bundle_path, "--url", url), show_locals=True, fake_httpx=True
    )
    assert code == 2, output
    assert "Traceback" not in output
    assert TOKEN.partition(".")[2] not in output


def test_an_unforeseen_error_after_the_token_is_read_never_prints_it(bundle_path):
    """The belt and braces: if something nobody anticipated escapes submit after the token
    is in hand, the app's own explicit setting keeps the locals (and the token) out of the
    output, even with Typer's old show-locals default restored underneath it."""
    code, output = _run_real_cli(_submit_args(bundle_path), show_locals=None, fake_httpx=True)
    assert code != 0
    assert "an error nothing anticipated" in output
    assert TOKEN.partition(".")[2] not in output


def test_the_harness_would_see_a_leak(bundle_path):
    """Negative control for the two tests above: with the old default forced back on, the
    same unforeseen error DOES print the token, so their silence is not a blind spot."""
    pytest.importorskip("rich")
    code, output = _run_real_cli(_submit_args(bundle_path), show_locals=True, fake_httpx=True)
    assert code != 0
    assert TOKEN.partition(".")[2] in output


def test_the_https_rule_still_applies_and_the_token_is_not_sent(bundle_path, fake):
    result = _submit(
        bundle_path,
        "--org-token-env",
        ENV,
        "--url",
        "http://127.0.0.1/v1/org/upload",
        env={ENV: TOKEN},
    )
    assert result.exit_code == 2  # loopback http still needs --allow-insecure-http
    assert "https" in _text(result)
    assert fake.calls == []


def test_an_unverifiable_bundle_is_refused_before_the_token_is_read(tmp_path, fake, bundle_path):
    # Read the scanned file, not stdout: click before 8.2 mixes stderr into stdout.
    data = json.loads(bundle_path.read_text(encoding="utf-8"))
    data["identity"]["ecc384_id"] = "tampered"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    result = _submit(path, "--org-token-env", ENV, env={})  # the variable is not even set
    assert result.exit_code == 2
    assert "does not verify" in _text(result)
    assert fake.calls == []


# ----------------------------------------------------------------- refusals from the platform


def _refusal(code: str, message: str) -> str:
    return json.dumps({"detail": {"code": code, "message": message}})


def test_an_unregistered_signer_refusal_says_how_to_register_the_key(bundle_path, monkeypatch):
    fake = _fake_httpx(
        status_code=403,
        body=_refusal(
            "unregistered_signer",
            "the bundle is not signed with an active signing key registered to this "
            "organization",
        ),
    )
    monkeypatch.setitem(sys.modules, "httpx", fake)
    result = _submit(bundle_path, "--org-token-env", ENV, env={ENV: TOKEN})
    assert result.exit_code == 4
    text = _text(result)
    assert "unregistered_signer" in text
    assert "voltry key fingerprint" in text
    assert "voltry key register" in text
    assert TOKEN.partition(".")[2] not in text


def test_an_invalid_token_refusal_is_reported_without_the_token(bundle_path, monkeypatch):
    fake = _fake_httpx(
        status_code=401,
        body=_refusal("invalid_upload_token", "the presented upload token is not valid"),
    )
    monkeypatch.setitem(sys.modules, "httpx", fake)
    result = _submit(bundle_path, "--org-token-env", ENV, env={ENV: TOKEN})
    assert result.exit_code == 4
    assert "invalid_upload_token" in _text(result)
    assert TOKEN.partition(".")[2] not in _text(result)


# ----------------------------------------------------------------- unchanged without the flag


def test_without_the_flag_submit_is_unchanged(bundle_path, fake):
    result = _submit(bundle_path, env={ENV: TOKEN})  # a token in the environment is ignored
    assert result.exit_code == 0, _text(result)
    (call,) = fake.calls
    assert call["url"] == DEFAULT_INGEST_URL + "?consent=true"
    assert call["headers"] == {"content-type": "application/json"}


def test_without_the_flag_the_signer_hint_is_the_old_one(bundle_path, monkeypatch):
    fake = _fake_httpx(
        status_code=403, body=_refusal("unauthorized_signer", "bundle signer is not authorized")
    )
    monkeypatch.setitem(sys.modules, "httpx", fake)
    result = _submit(bundle_path)
    assert result.exit_code == 4
    assert "must be registered with Voltry" in _text(result)
    assert "voltry key fingerprint" not in _text(result)


def test_no_option_takes_the_token_itself():
    """The only way in is an environment variable NAME."""
    import typer.main

    command = typer.main.get_command(app)
    submit = command.commands["submit"]  # type: ignore[attr-defined]
    options = {opt for param in submit.params for opt in getattr(param, "opts", [])}
    assert "--org-token-env" in options
    assert not {o for o in options if "token" in o} - {"--org-token-env"}
    help_text = runner.invoke(app, ["submit", "--help"], terminal_width=200).output
    assert "environment" in help_text


def test_the_token_grammar_matches_the_platform():
    """The platform's grammar (services/platform-api/app/org_upload/tokens.py) is pinned to
    the same literal in its own suite."""
    assert cli_module._UPLOAD_TOKEN_RE.pattern == r"vot_[0-9a-f]{24}\.[A-Za-z0-9_-]{16,128}"
    assert cli_module._UPLOAD_TOKEN_RE.fullmatch(TOKEN)
