"""
Unit tests for the HMAC token generator (auth.utils.tokens).

These tests use simple mock objects — no database or async needed.
"""
from __future__ import annotations

import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from auth.utils.tokens import TokenGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(
    user_id: int = 1,
    password: str = "hashed_pw_abc123",
    last_login=None,
    is_active: bool = True,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=user_id,
        password=password,
        last_login=last_login,
        is_active=is_active,
    )


def _make_email_address(
    email: str = "user@example.com",
    verified: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(email=email, verified=verified)


@pytest.fixture
def generator() -> TokenGenerator:
    return TokenGenerator(purpose="test-purpose", max_age_seconds=3600)


@pytest.fixture
def user() -> SimpleNamespace:
    return _make_user()


@pytest.fixture
def email_address() -> SimpleNamespace:
    return _make_email_address()


# ---------------------------------------------------------------------------
# 1. make_token produces a non-empty string
# ---------------------------------------------------------------------------

class TestMakeToken:
    def test_produces_non_empty_string(self, generator, user):
        token = generator.make_token(user)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_produces_non_empty_string_with_email(self, generator, user, email_address):
        token = generator.make_token(user, email_address=email_address)
        assert isinstance(token, str)
        assert len(token) > 0


# ---------------------------------------------------------------------------
# 2. validate_token correctly extracts user_id
# ---------------------------------------------------------------------------

class TestValidateToken:
    def test_extracts_user_id(self, generator, user):
        token = generator.make_token(user)
        user_id, valid = generator.validate_token(token)
        assert valid is True
        assert user_id == user.id

    def test_extracts_user_id_different_users(self, generator):
        for uid in (1, 42, 9999):
            user = _make_user(user_id=uid)
            token = generator.make_token(user)
            user_id, valid = generator.validate_token(token)
            assert valid is True
            assert user_id == uid


# ---------------------------------------------------------------------------
# 3. validate_token returns (0, False) for garbage input
# ---------------------------------------------------------------------------

class TestValidateTokenGarbage:
    @pytest.mark.parametrize("bad_token", [
        "",
        "not-a-token",
        "!!!invalid-base64???",
        "AAAA",  # valid base64 but wrong structure
    ])
    def test_garbage_input(self, generator, bad_token):
        user_id, valid = generator.validate_token(bad_token)
        assert user_id == 0
        assert valid is False


# ---------------------------------------------------------------------------
# 4. check_token validates a token correctly
# ---------------------------------------------------------------------------

class TestCheckToken:
    def test_valid_token(self, generator, user):
        token = generator.make_token(user)
        assert generator.check_token(user, token) is True

    def test_valid_token_with_email(self, generator, user, email_address):
        token = generator.make_token(user, email_address=email_address)
        assert generator.check_token(user, token, email_address=email_address) is True


# ---------------------------------------------------------------------------
# 5. check_token rejects expired tokens
# ---------------------------------------------------------------------------

class TestCheckTokenExpired:
    def test_expired_token(self, user):
        generator = TokenGenerator(purpose="test-purpose", max_age_seconds=60)
        creation_time = time.time()

        with patch("auth.utils.tokens.time.time", return_value=creation_time):
            token = generator.make_token(user)

        # Advance time past max_age_seconds
        expired_time = creation_time + 61
        with patch("auth.utils.tokens.time.time", return_value=expired_time):
            assert generator.check_token(user, token) is False

    def test_not_yet_expired_token(self, user):
        generator = TokenGenerator(purpose="test-purpose", max_age_seconds=60)
        creation_time = time.time()

        with patch("auth.utils.tokens.time.time", return_value=creation_time):
            token = generator.make_token(user)

        # Still within max_age_seconds
        still_valid_time = creation_time + 59
        with patch("auth.utils.tokens.time.time", return_value=still_valid_time):
            assert generator.check_token(user, token) is True


# ---------------------------------------------------------------------------
# 6. check_token rejects tampered tokens
# ---------------------------------------------------------------------------

class TestCheckTokenTampered:
    def test_tampered_token(self, generator, user):
        token = generator.make_token(user)
        # Flip a character in the middle of the token
        mid = len(token) // 2
        tampered_char = "A" if token[mid] != "A" else "B"
        tampered = token[:mid] + tampered_char + token[mid + 1:]
        assert generator.check_token(user, tampered) is False

    def test_truncated_token(self, generator, user):
        token = generator.make_token(user)
        truncated = token[:10]
        assert generator.check_token(user, truncated) is False


# ---------------------------------------------------------------------------
# 7. check_token rejects token for wrong user
# ---------------------------------------------------------------------------

class TestCheckTokenWrongUser:
    def test_wrong_user(self, generator):
        user_a = _make_user(user_id=1)
        user_b = _make_user(user_id=2)
        token = generator.make_token(user_a)
        assert generator.check_token(user_b, token) is False


# ---------------------------------------------------------------------------
# 8. Different purposes produce different tokens
# ---------------------------------------------------------------------------

class TestDifferentPurposes:
    def test_different_purpose_different_token(self, user):
        gen_verify = TokenGenerator(purpose="email-verify", max_age_seconds=3600)
        gen_reset = TokenGenerator(purpose="password-reset", max_age_seconds=3600)

        now = time.time()
        with patch("auth.utils.tokens.time.time", return_value=now):
            token_verify = gen_verify.make_token(user)
            token_reset = gen_reset.make_token(user)

        assert token_verify != token_reset

    def test_cross_purpose_rejection(self, user):
        gen_verify = TokenGenerator(purpose="email-verify", max_age_seconds=3600)
        gen_reset = TokenGenerator(purpose="password-reset", max_age_seconds=3600)

        token_verify = gen_verify.make_token(user)
        token_reset = gen_reset.make_token(user)

        # Each generator should reject the other's token
        assert gen_verify.check_token(user, token_reset) is False
        assert gen_reset.check_token(user, token_verify) is False


# ---------------------------------------------------------------------------
# 9. Token auto-invalidates after password change
# ---------------------------------------------------------------------------

class TestPasswordChangeInvalidation:
    def test_password_change_invalidates_token(self, generator):
        user = _make_user(password="old_password_hash")
        token = generator.make_token(user)

        assert generator.check_token(user, token) is True

        # Simulate password change
        user.password = "new_password_hash"
        assert generator.check_token(user, token) is False


# ---------------------------------------------------------------------------
# 10. Token auto-invalidates after email_address.verified changes
# ---------------------------------------------------------------------------

class TestEmailVerifiedInvalidation:
    def test_verified_change_invalidates_token(self, generator, user):
        email_addr = _make_email_address(verified=False)
        token = generator.make_token(user, email_address=email_addr)

        assert generator.check_token(user, token, email_address=email_addr) is True

        # Simulate email verification
        email_addr.verified = True
        assert generator.check_token(user, token, email_address=email_addr) is False
