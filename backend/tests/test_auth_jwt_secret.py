"""
Tests for JWT secret key security remediation (CWE-798).

Validates that:
  - JWT_SECRET_KEY is loaded from an environment variable, not hardcoded.
  - auth module raises RuntimeError when the env var is absent/empty.
  - generate_token / verify_token work correctly when the env var is set.
  - Tokens signed with a wrong key are rejected (verify_token returns None).
"""
import importlib
import os
import sys
import unittest

# Ensure the backend package root is on the path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helper: reload config + auth modules with a controlled environment.
# ---------------------------------------------------------------------------

def _reload_modules(env_overrides):
    """
    Reload `config` and `auth` with the given environment variables in place.
    Returns the reloaded `auth` module, or re-raises any exception that
    occurs during import/reload (e.g. RuntimeError for missing secret).
    """
    original_env = os.environ.copy()
    try:
        os.environ.update(env_overrides)
        # Remove JWT_SECRET_KEY if the caller explicitly set it to None.
        for k, v in env_overrides.items():
            if v is None:
                os.environ.pop(k, None)

        import config as config_mod
        importlib.reload(config_mod)

        import auth as auth_mod
        importlib.reload(auth_mod)
        return auth_mod
    finally:
        # Restore original environment.
        os.environ.clear()
        os.environ.update(original_env)


# ---------------------------------------------------------------------------
# Config-level tests
# ---------------------------------------------------------------------------

class TestConfigJwtSecretKeyFromEnv(unittest.TestCase):
    """Config.JWT_SECRET_KEY must be sourced from the environment, not hardcoded."""

    def test_secret_key_is_none_when_env_var_absent(self):
        """Config.JWT_SECRET_KEY must be None (not a hardcoded fallback) when the env var is unset."""
        original = os.environ.pop('JWT_SECRET_KEY', None)
        try:
            import config as config_mod
            importlib.reload(config_mod)
            # The fix removes the hardcoded default; value must be None.
            self.assertIsNone(config_mod.Config.JWT_SECRET_KEY)
        finally:
            if original is not None:
                os.environ['JWT_SECRET_KEY'] = original
            import config as config_mod
            importlib.reload(config_mod)

    def test_secret_key_reads_from_env_var(self):
        """Config.JWT_SECRET_KEY must equal the value of JWT_SECRET_KEY env var."""
        test_secret = 'env-driven-secret-value-for-test'
        original = os.environ.get('JWT_SECRET_KEY')
        os.environ['JWT_SECRET_KEY'] = test_secret
        try:
            import config as config_mod
            importlib.reload(config_mod)
            self.assertEqual(config_mod.Config.JWT_SECRET_KEY, test_secret)
        finally:
            if original is None:
                os.environ.pop('JWT_SECRET_KEY', None)
            else:
                os.environ['JWT_SECRET_KEY'] = original
            import config as config_mod
            importlib.reload(config_mod)

    def test_hardcoded_secret_value_not_present(self):
        """The old hardcoded secret 'secret_key_12345' must not appear as the configured value."""
        import config as config_mod
        importlib.reload(config_mod)
        # Even if JWT_SECRET_KEY happens to be set in this environment,
        # it must never equal the old hardcoded literal.
        self.assertNotEqual(config_mod.Config.JWT_SECRET_KEY, 'secret_key_12345')


# ---------------------------------------------------------------------------
# Auth module – fail-fast guard tests
# ---------------------------------------------------------------------------

class TestAuthFailsWithoutSecret(unittest.TestCase):
    """auth module must raise RuntimeError when JWT_SECRET_KEY is not configured."""

    def test_import_raises_when_env_var_missing(self):
        """Importing/reloading auth without JWT_SECRET_KEY must raise RuntimeError."""
        original = os.environ.pop('JWT_SECRET_KEY', None)
        try:
            import config as config_mod
            importlib.reload(config_mod)

            import auth as auth_mod
            with self.assertRaises(RuntimeError):
                importlib.reload(auth_mod)
        finally:
            if original is not None:
                os.environ['JWT_SECRET_KEY'] = original
            # Restore modules to a working state.
            import config as config_mod
            importlib.reload(config_mod)

    def test_import_raises_when_env_var_is_empty_string(self):
        """Importing/reloading auth with JWT_SECRET_KEY='' must raise RuntimeError."""
        original = os.environ.get('JWT_SECRET_KEY')
        os.environ['JWT_SECRET_KEY'] = ''
        try:
            import config as config_mod
            importlib.reload(config_mod)

            import auth as auth_mod
            with self.assertRaises(RuntimeError):
                importlib.reload(auth_mod)
        finally:
            if original is None:
                os.environ.pop('JWT_SECRET_KEY', None)
            else:
                os.environ['JWT_SECRET_KEY'] = original
            import config as config_mod
            importlib.reload(config_mod)


# ---------------------------------------------------------------------------
# Token generation / verification tests (requires env var to be set)
# ---------------------------------------------------------------------------

class TestJwtTokenOperations(unittest.TestCase):
    """generate_token and verify_token must work correctly with a valid env-provided secret."""

    # A strong random-looking test secret; never used in production.
    TEST_SECRET = 'Xk9#mP2!qR7nL4vT8wY1jZ6hA3bN0cE5'

    def setUp(self):
        """Set the JWT_SECRET_KEY env var and reload modules before each test."""
        self._original_secret = os.environ.get('JWT_SECRET_KEY')
        os.environ['JWT_SECRET_KEY'] = self.TEST_SECRET

        import config as config_mod
        importlib.reload(config_mod)
        import auth as auth_mod
        importlib.reload(auth_mod)
        self.auth = auth_mod

    def tearDown(self):
        """Restore the original environment and reload modules."""
        if self._original_secret is None:
            os.environ.pop('JWT_SECRET_KEY', None)
        else:
            os.environ['JWT_SECRET_KEY'] = self._original_secret
        import config as config_mod
        importlib.reload(config_mod)

    def test_generate_token_returns_string(self):
        """generate_token must return a non-empty string."""
        token = self.auth.generate_token(1, 'alice')
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 0)

    def test_verify_token_returns_payload_for_valid_token(self):
        """verify_token must decode a token produced by generate_token."""
        token = self.auth.generate_token(42, 'bob')
        payload = self.auth.verify_token(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload['user_id'], 42)
        self.assertEqual(payload['username'], 'bob')

    def test_verify_token_returns_none_for_tampered_token(self):
        """verify_token must return None for a token with a modified payload."""
        token = self.auth.generate_token(1, 'alice')
        # Flip one character in the signature segment to corrupt the token.
        parts = token.split('.')
        if len(parts) == 3:
            sig = parts[2]
            # Toggle the last character to corrupt the signature.
            corrupted_sig = sig[:-1] + ('A' if sig[-1] != 'A' else 'B')
            tampered = '.'.join([parts[0], parts[1], corrupted_sig])
            result = self.auth.verify_token(tampered)
            self.assertIsNone(result)

    def test_verify_token_returns_none_for_wrong_secret(self):
        """A token signed with a different secret must be rejected."""
        import jwt
        wrong_payload = {'user_id': 99, 'username': 'hacker'}
        # Sign with a completely different secret.
        forged_token = jwt.encode(wrong_payload, 'wrong-secret', algorithm='HS256')
        if isinstance(forged_token, bytes):
            forged_token = forged_token.decode('utf-8')
        result = self.auth.verify_token(forged_token)
        self.assertIsNone(result)

    def test_verify_token_returns_none_for_garbage_input(self):
        """verify_token must return None (not raise) for arbitrary garbage input."""
        self.assertIsNone(self.auth.verify_token('not.a.token'))
        self.assertIsNone(self.auth.verify_token(''))

    def test_token_does_not_contain_hardcoded_secret(self):
        """The hardcoded secret 'secret_key_12345' must NOT be able to verify a production token."""
        import jwt
        token = self.auth.generate_token(1, 'alice')
        with self.assertRaises(Exception):
            # Decoding with the old hardcoded secret must fail because the
            # token was signed with TEST_SECRET, not 'secret_key_12345'.
            jwt.decode(token, 'secret_key_12345', algorithms=['HS256'])


if __name__ == '__main__':
    unittest.main()
