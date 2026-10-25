from __future__ import annotations

import pytest
from conftest import FAKE_AWS_KEY, FAKE_DB_PASSWORD, FAKE_GH_TOKEN

from auditor.redact import contains_secret, is_placeholder, redact, redact_obj


@pytest.mark.parametrize(
    "text, secret",
    [
        (f'key = "{FAKE_AWS_KEY}"', FAKE_AWS_KEY),
        (f"GITHUB_TOKEN={FAKE_GH_TOKEN}", FAKE_GH_TOKEN),
        (f"DB_PASSWORD={FAKE_DB_PASSWORD}", FAKE_DB_PASSWORD),
        (f'"password": "{FAKE_DB_PASSWORD}"', FAKE_DB_PASSWORD),
        (f"  api_key: '{FAKE_DB_PASSWORD}'", FAKE_DB_PASSWORD),
        (f"postgres://admin:{FAKE_DB_PASSWORD}@db:5432/app", FAKE_DB_PASSWORD),
        ("OPENAI_API_KEY=sk-" + "proj-abcdefghijklmnopqrstuvwx1234", "abcdefghijklmnopqrstuvwx1234"),
        (f"ENV ORDERS_API_TOKEN={FAKE_DB_PASSWORD}", FAKE_DB_PASSWORD),
        ("ENV API_TOKEN tok_" + "9f8e7d6c5b4a39281706", "9f8e7d6c5b4a39281706"),
    ],
)
def test_secrets_are_masked(text, secret):
    out = redact(text)
    assert secret not in out
    assert "[REDACTED:" in out


@pytest.mark.parametrize(
    "text",
    [
        "DB_PASSWORD=changeme",
        "API_KEY=your-api-key-here",
        'token = os.environ["TOKEN"]',
        "password: ${{ secrets.DB_PASSWORD }}",
        "SECRET_KEY=${SECRET_KEY}",
        "password = settings.DB_PASSWORD",
        "api_key: str",
        'password = ""',
        '{"id-token": "write"}',
        "  id-token: write",
        "TOKEN_TTL=3600",
    ],
)
def test_placeholders_and_references_are_kept(text):
    assert redact(text) == text


def test_private_key_body_masked_and_line_count_preserved():
    body = "MIIEowIBAAKCAQEA" + "x" * 48
    text = "a\n-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n" + body + "\n-----END RSA PRIVATE KEY-----\nb"
    out = redact(text)
    assert body not in out
    assert out.count("\n") == text.count("\n")
    assert out.endswith("b")


def test_redact_obj_and_helpers():
    data = {"a": [f"k={FAKE_GH_TOKEN}"], "n": 3}
    out = redact_obj(data)
    assert FAKE_GH_TOKEN not in str(out) and out["n"] == 3
    assert contains_secret(FAKE_AWS_KEY) and not contains_secret("hello world")
    assert is_placeholder("<your-token>") and not is_placeholder(FAKE_DB_PASSWORD)
