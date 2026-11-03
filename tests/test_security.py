"""Phase 16 security tests: tokens, rate limits, TLS and error shape."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cloudsentinel.api import create_app
from cloudsentinel.cli import _security_banner, _serve, build_parser
from cloudsentinel.ratelimit import SlidingWindowLimiter
from cloudsentinel.tokens import TokenError, TokenStore

TOKEN = "test-token-value-1234567890"


# --------------------------------------------------------------------- tokens


def test_add_returns_strong_unique_tokens(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")

    first, first_record = store.add(label="phone")
    second, second_record = store.add(label="desktop")

    assert first != second
    assert len(first) >= 32
    assert first_record.label == "phone"
    assert second_record.label == "desktop"
    assert store.active_count() == 2


def test_store_never_contains_plaintext(tmp_path):
    path = tmp_path / "tokens.json"
    store = TokenStore(path)

    plaintext, record = store.add(label="phone")

    raw = path.read_text(encoding="utf-8")
    assert plaintext not in raw
    # The salted digest is stored (needed for constant-time checks), the token
    # itself never is.
    assert record.digest in raw
    assert "salt" in json.loads(raw)


def test_verify_accepts_active_and_rejects_unknown(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    plaintext, _ = store.add()

    assert store.verify(plaintext) is True
    assert store.verify("wrong") is False
    assert store.verify("") is False


def test_revoke_by_label_blocks_the_token(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    plaintext, _ = store.add(label="phone")
    store.add(label="tablet")

    assert store.revoke("phone") == 1
    assert store.verify(plaintext) is False
    assert store.active_count() == 1


def test_revoke_by_fingerprint_prefix(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    plaintext, record = store.add(label="phone")

    assert store.revoke(record.digest[:6]) == 1
    assert store.verify(plaintext) is False


def test_duplicate_label_is_rejected(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    store.add(label="phone")

    with pytest.raises(TokenError):
        store.add(label="phone")


def test_listing_never_exposes_digests(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    store.add(label="phone")

    listing = store.listing()[0]

    assert set(listing) == {
        "label",
        "fingerprint",
        "created",
        "revoked",
        "last_used",
        "active",
        "role",
    }
    assert len(listing["fingerprint"]) == 8


def test_salts_differ_between_stores(tmp_path):
    first_store = TokenStore(tmp_path / "a.json")
    second_store = TokenStore(tmp_path / "b.json")
    first_store._save()
    second_store._save()

    first = json.loads((tmp_path / "a.json").read_text(encoding="utf-8"))
    second = json.loads((tmp_path / "b.json").read_text(encoding="utf-8"))

    assert first["salt"] != second["salt"]


def test_key_file_is_owner_only_on_posix(tmp_path):
    if sys.platform == "win32":
        pytest.skip("POSIX permission bits are not meaningful on Windows")

    path = tmp_path / "tokens.json"
    TokenStore(path).add()

    assert path.stat().st_mode & 0o077 == 0


# ------------------------------------------------------------------------ API


def _app(tmp_path, **kwargs):
    database = tmp_path / "api.db"
    return create_app(db_path=database, raw_dir=tmp_path / "raw", **kwargs)


def test_store_token_authenticates(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    plaintext, _ = store.add(label="phone")

    with TestClient(_app(tmp_path, token="", token_store=store)) as client:
        assert client.get("/api/summary").status_code == 401
        response = client.get(
            "/api/summary", headers={"X-API-Token": plaintext}
        )
        assert response.status_code == 200


def test_revoked_token_is_rejected(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    plaintext, _ = store.add(label="phone")
    store.revoke("phone")

    with TestClient(_app(tmp_path, token="", token_store=store)) as client:
        response = client.get("/api/summary", headers={"X-API-Token": plaintext})

    assert response.status_code == 401


def test_empty_store_locks_the_api(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")

    with TestClient(_app(tmp_path, token="", token_store=store)) as client:
        assert client.get("/api/summary").status_code == 401
        assert client.get("/health").json()["auth_required"] is True


def test_bootstrap_and_store_tokens_both_work(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    rotating, _ = store.add(label="phone")

    with TestClient(_app(tmp_path, token=TOKEN, token_store=store)) as client:
        assert (
            client.get("/api/summary", headers={"X-API-Token": TOKEN}).status_code
            == 200
        )
        assert (
            client.get("/api/summary", headers={"X-API-Token": rotating}).status_code
            == 200
        )


def test_bearer_header_is_accepted(tmp_path):
    with TestClient(_app(tmp_path, token=TOKEN)) as client:
        response = client.get(
            "/api/summary", headers={"Authorization": f"Bearer {TOKEN}"}
        )

    assert response.status_code == 200


def test_401_advertises_bearer(tmp_path):
    with TestClient(_app(tmp_path, token=TOKEN)) as client:
        response = client.get("/api/summary")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_health_reports_security_posture(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")
    store.add(label="phone")

    with TestClient(_app(tmp_path, token="", token_store=store)) as client:
        payload = client.get("/health").json()
    assert payload["auth_required"] is True
    assert payload["auth_mode"] == "token-store"
    assert payload["rate_limit_per_minute"] == 120

    with TestClient(_app(tmp_path)) as open_client:
        open_payload = open_client.get("/health").json()
    assert open_payload["auth_mode"] == "open"
    assert open_payload["auth_required"] is False


def test_security_headers_are_set(tmp_path):
    with TestClient(_app(tmp_path, token=TOKEN)) as client:
        response = client.get("/health")

    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"


def test_validation_errors_have_uniform_shape(tmp_path):
    with TestClient(_app(tmp_path, token=TOKEN)) as client:
        response = client.get(
            "/api/alerts", headers={"X-API-Token": TOKEN}, params={"limit": 999}
        )

    assert response.status_code == 422
    payload = response.json()
    assert payload["detail"] == "invalid request parameters"
    assert isinstance(payload["errors"], list)


def test_cors_defaults_to_loopback_origins(tmp_path):
    with TestClient(_app(tmp_path, token=TOKEN)) as client:
        allowed = client.get(
            "/health", headers={"Origin": "http://127.0.0.1:61234"}
        )
        blocked = client.get("/health", headers={"Origin": "http://evil.example"})

    assert allowed.headers["access-control-allow-origin"] == "http://127.0.0.1:61234"
    assert "access-control-allow-origin" not in blocked.headers


# ---------------------------------------------------------------- rate limits


def test_limiter_allows_then_returns_retry_after():
    now = [100.0]
    limiter = SlidingWindowLimiter(2, 60, clock=lambda: now[0])

    assert limiter.check("a") == (True, 0)
    assert limiter.check("a") == (True, 0)
    allowed, retry_after = limiter.check("a")
    assert allowed is False
    assert 1 <= retry_after <= 60

    # The window slides: after 60 seconds the budget is restored.
    now[0] += 61
    assert limiter.check("a") == (True, 0)


def test_limiter_is_per_key_and_can_be_disabled():
    now = [0.0]
    limiter = SlidingWindowLimiter(1, 60, clock=lambda: now[0])

    assert limiter.check("a")[0] is True
    assert limiter.check("b")[0] is True
    assert limiter.check("a")[0] is False

    disabled = SlidingWindowLimiter(0)
    assert disabled.enabled is False
    assert disabled.check("a") == (True, 0)


def test_api_rate_limit_returns_429(tmp_path):
    with TestClient(_app(tmp_path, token=TOKEN, rate_limit=3)) as client:
        headers = {"X-API-Token": TOKEN}
        for _ in range(3):
            assert client.get("/api/summary", headers=headers).status_code == 200

        blocked = client.get("/api/summary", headers=headers)

    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1
    assert blocked.json()["detail"] == "rate limit exceeded"


def test_health_is_exempt_from_rate_limits(tmp_path):
    with TestClient(_app(tmp_path, token=TOKEN, rate_limit=1)) as client:
        for _ in range(5):
            assert client.get("/health").status_code == 200


def test_scan_has_a_stricter_budget(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "events.json").write_text(
        json.dumps(
            [
                {
                    "timestamp": "2026-04-01T10:00:00Z",
                    "event_source": "aws.signin",
                    "event_name": "ConsoleLogin",
                    "user": "mallory",
                    "source_ip": "203.0.113.9",
                    "status": "failure",
                }
            ]
        ),
        encoding="utf-8",
    )

    app = create_app(
        db_path=tmp_path / "scan.db",
        raw_dir=raw,
        token=TOKEN,
        allow_scan=True,
        rate_limit=10,
    )
    with TestClient(app) as client:
        headers = {"X-API-Token": TOKEN}
        assert client.post("/api/scan", headers=headers).status_code == 200
        blocked = client.post("/api/scan", headers=headers)

    assert blocked.status_code == 429
    assert blocked.json()["detail"] == "rate limit exceeded"


# ------------------------------------------------------------------------ CLI


def test_serve_parser_accepts_security_flags():
    args = build_parser().parse_args(
        [
            "serve",
            "--tls-cert",
            "certs/a.pem",
            "--tls-key",
            "certs/a-key.pem",
            "--rate-limit",
            "30",
            "--token-file",
            "data/tokens.json",
        ]
    )

    assert args.tls_cert == "certs/a.pem"
    assert args.tls_key == "certs/a-key.pem"
    assert args.rate_limit == 30
    assert args.token_file == "data/tokens.json"


def test_serve_rejects_half_a_tls_pair(tmp_path, capsys):
    args = build_parser().parse_args(
        ["serve", "--tls-cert", str(tmp_path / "cert.pem"), "--db", str(tmp_path / "x.db")]
    )

    assert _serve(args) == 2
    assert "--tls-cert and --tls-key" in capsys.readouterr().out


def test_serve_rejects_missing_certificate(tmp_path, capsys):
    args = build_parser().parse_args(
        [
            "serve",
            "--tls-cert",
            str(tmp_path / "missing.pem"),
            "--tls-key",
            str(tmp_path / "missing-key.pem"),
        ]
    )

    assert _serve(args) == 2
    assert "file not found" in capsys.readouterr().out


def test_serve_rejects_negative_rate_limit(tmp_path, capsys):
    args = build_parser().parse_args(
        ["serve", "--rate-limit", "-1", "--db", str(tmp_path / "x.db")]
    )

    assert _serve(args) == 2
    assert "must be 0" in capsys.readouterr().out


def test_serve_passes_tls_to_uvicorn(tmp_path, monkeypatch):
    import uvicorn

    captured: dict = {}

    def fake_run(app, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)

    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("dummy", encoding="utf-8")
    key.write_text("dummy", encoding="utf-8")

    args = build_parser().parse_args(
        [
            "serve",
            "--port",
            "9443",
            "--db",
            str(tmp_path / "serve.db"),
            "--token",
            TOKEN,
            "--tls-cert",
            str(cert),
            "--tls-key",
            str(key),
        ]
    )

    assert _serve(args) == 0
    assert captured["ssl_certfile"] == str(cert)
    assert captured["ssl_keyfile"] == str(key)
    assert captured["port"] == 9443


def test_security_banner_warns_on_plain_lan():
    lines = _security_banner("0.0.0.0", tls=False, bootstrap_token=True, rate_limit=120)

    joined = "\n".join(lines)
    assert "plain HTTP" in joined
    assert "TLS            : off" in joined
    assert any("WARNING" in line for line in lines)


def test_security_banner_is_quiet_on_loopback():
    lines = _security_banner("127.0.0.1", tls=True, bootstrap_token=True, rate_limit=120)

    assert all("WARNING" not in line for line in lines)
    assert "TLS            : on" in "\n".join(lines)


def test_security_banner_reports_open_mode():
    lines = _security_banner("0.0.0.0", tls=True, bootstrap_token=False, rate_limit=0)

    joined = "\n".join(lines)
    assert "OPEN" in joined
    assert "Rate limit     : off" in joined


def test_security_banner_reports_locked_store(tmp_path):
    store = TokenStore(tmp_path / "tokens.json")

    lines = _security_banner(
        "127.0.0.1", tls=True, bootstrap_token=False, token_store=store, rate_limit=120
    )

    joined = "\n".join(lines)
    assert "LOCKED" in joined
    assert "OPEN" not in joined


# ------------------------------------------------------------- certificate tool


def test_certificate_includes_lan_and_loopback_sans(tmp_path):
    from cryptography import x509

    from scripts.make_dev_cert import write_certificate

    cert_path, key_path = write_certificate(
        tmp_path, ips=["192.168.1.50"], dns=["cloudsentinel.local"]
    )

    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    sans = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value

    assert "localhost" in sans.get_values_for_type(x509.DNSName)
    assert "cloudsentinel.local" in sans.get_values_for_type(x509.DNSName)
    addresses = {str(item) for item in sans.get_values_for_type(x509.IPAddress)}
    assert {"127.0.0.1", "192.168.1.50"} <= addresses
    assert key_path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")


def test_certificate_refuses_to_overwrite(tmp_path):
    from scripts.make_dev_cert import write_certificate

    write_certificate(tmp_path, ips=[])

    with pytest.raises(FileExistsError):
        write_certificate(tmp_path, ips=[])
    # Forcing replaces it.
    assert write_certificate(tmp_path, ips=[], force=True)


def test_certificate_days_are_validated(tmp_path):
    from scripts.make_dev_cert import build_certificate

    with pytest.raises(ValueError):
        build_certificate(days=0)
    with pytest.raises(ValueError):
        build_certificate(days=4000)


def test_legacy_tokens_map_to_analyst(tmp_path):
    path = tmp_path / "legacy.json"
    store = TokenStore(path)
    plaintext, _ = store.add(label="legacy")

    data = json.loads(path.read_text(encoding="utf-8"))
    for item in data["tokens"]:
        item.pop("role", None)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data), encoding="utf-8")
    temporary.replace(path)

    reloaded = TokenStore(path)
    record = reloaded.verify_record(plaintext)
    assert record is not None
    assert record.role == "analyst"
    assert reloaded.listing()[0]["role"] == "analyst"


def test_tokens_carry_roles(tmp_path):
    store = TokenStore(tmp_path / "roles.json")

    admin_plain, admin = store.add(label="ci", role="admin")
    viewer_plain, viewer = store.add(label="report", role="viewer")

    matched_admin = store.verify_record(admin_plain)
    matched_viewer = store.verify_record(viewer_plain)

    assert matched_admin is not None and matched_admin.role == "admin"
    assert matched_viewer is not None and matched_viewer.role == "viewer"
    assert store.verify_record(admin_plain + "x") is None
