"""
Tests to verify that JWT_SECRET_KEY is never hardcoded and is always sourced
from the environment (CWE-798: Use of Hard-coded Credentials).

These tests exercise:
  1. config.py — JWT_SECRET_KEY must come from os.environ, not a literal.
  2. auth._get_jwt_secret() — must raise when no secret is configured.
  3. auth.generate_token / verify_token — functional round-trip when a secret
     is injected via the Flask app config (TestConfig pattern).
"""
import sys
import os
import importlib
import inspect
import unittest

# Make the backend package importable.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helper: build a minimal Flask app with a given JWT_SECRET_KEY value so that
# _get_jwt_secret() uses current_app.config (matching the production path).
# ---------------------------------------------------------------------------

def _make_app(jwt_secret):
    from flask import Flask
    from models import db
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = jwt_secret
    app.config['JWT_ALGORITHM'] = 'HS256'
    db.init_app(app)
    return app


# ---------------------------------------------------------------------------
# 1. Config-level tests: JWT_SECRET_KEY must not be a hardcoded literal.
# ---------------------------------------------------------------------------

class TestConfigNoHardcodedSecret(unittest.TestCase):
    """Ensure config.py derives JWT_SECRET_KEY from the environment."""

    def test_jwt_secret_key_is_not_hardcoded_literal(self):
        """JWT_SECRET_KEY class attribute must NOT be a string literal."""
        from config import Config
        # Inspect the source of Config to confirm there is no string assignment
        # like JWT_SECRET_KEY = "some_literal".
        source = inspect.getsource(Config)
        # The assignment must reference os.environ, not a bare string literal.
        self.assertIn(
            'os.environ',
            source,
            "JWT_SECRET_KEY must be assigned from os.environ, not a hardcoded value."
        )

    def test_jwt_secret_key_is_none_without_env_var(self):
        """Without JWT_SECRET_KEY in the environment, Config.JWT_SECRET_KEY is None."""
        # Remove the variable if it happens to be set in the current process.
        original = os.environ.pop('JWT_SECRET_KEY', None)
        try:
            # Re-import to pick up the cleared environment.
            import config as config_module
            importlib.reload(config_module)
            self.assertIsNone(
                config_module.Config.JWT_SECRET_KEY,
                "Config.JWT_SECRET_KEY must be None when env var is absent."
            )
        finally:
            if original is not None:
                os.environ['JWT_SECRET_KEY'] = original
            importlib.reload(importlib.import_module('config'))

    def test_jwt_secret_key_reads_from_environment(self):
        """Config.JWT_SECRET_KEY picks up the value set in the environment."""
        test_secret = 'env-provided-secret-xyz-987'
        original = os.environ.get('JWT_SECRET_KEY')
        os.environ['JWT_SECRET_KEY'] = test_secret
        try:
            import config as config_module
            importlib.reload(config_module)
            self.assertEqual(
                config_module.Config.JWT_SECRET_KEY,
                test_secret,
                "Config.JWT_SECRET_KEY must equal the value set in JWT_SECRET_KEY env var."
            )
        finally:
            if original is None:
                del os.environ['JWT_SECRET_KEY']
            else:
                os.environ['JWT_SECRET_KEY'] = original
            importlib.reload(importlib.import_module('config'))


# ---------------------------------------------------------------------------
# 2. _get_jwt_secret() raises when secret is absent.
# ---------------------------------------------------------------------------

class TestGetJwtSecretGuard(unittest.TestCase):
    """_get_jwt_secret() must raise RuntimeError when JWT_SECRET_KEY is unset."""

    def test_raises_when_app_config_has_no_secret(self):
        """RuntimeError is raised if JWT_SECRET_KEY is falsy in the app config."""
        app = _make_app(None)  # No secret configured.
        with app.app_context():
            import auth
            with self.assertRaises(RuntimeError) as ctx:
                auth._get_jwt_secret()
            self.assertIn('JWT_SECRET_KEY', str(ctx.exception))

    def test_raises_when_app_config_has_empty_string_secret(self):
        """RuntimeError is raised if JWT_SECRET_KEY is an empty string."""
        app = _make_app('')
        with app.app_context():
            import auth
            with self.assertRaises(RuntimeError):
                auth._get_jwt_secret()

    def test_returns_secret_when_configured(self):
        """_get_jwt_secret() returns the configured value when present."""
        secret = 'a-valid-test-secret-value'
        app = _make_app(secret)
        with app.app_context():
            import auth
            result = auth._get_jwt_secret()
            self.assertEqual(result, secret)


# ---------------------------------------------------------------------------
# 3. generate_token / verify_token functional round-trip.
# ---------------------------------------------------------------------------

class TestTokenRoundTrip(unittest.TestCase):
    """generate_token and verify_token work correctly with env-sourced secret."""

    def setUp(self):
        self.secret = 'test-only-secret-value-for-unit-tests'
        self.app = _make_app(self.secret)

    def test_generate_token_returns_string(self):
        """generate_token returns a non-empty string."""
        with self.app.app_context():
            import auth
            token = auth.generate_token(user_id=42, username='alice')
            self.assertIsInstance(token, str)
            self.assertTrue(len(token) > 0)

    def test_verify_token_decodes_valid_token(self):
        """verify_token successfully decodes a token produced by generate_token."""
        with self.app.app_context():
            import auth
            token = auth.generate_token(user_id=7, username='bob')
            payload = auth.verify_token(token)
            self.assertIsNotNone(payload)
            self.assertEqual(payload['user_id'], 7)
            self.assertEqual(payload['username'], 'bob')

    def test_verify_token_rejects_tampered_token(self):
        """verify_token returns None for a tampered token."""
        with self.app.app_context():
            import auth
            token = auth.generate_token(user_id=1, username='carol')
            # Flip the last character to simulate tampering.
            tampered = token[:-1] + ('A' if token[-1] != 'A' else 'B')
            result = auth.verify_token(tampered)
            self.assertIsNone(result)

    def test_verify_token_rejects_token_signed_with_different_secret(self):
        """verify_token returns None for a token signed with a different secret."""
        other_app = _make_app('completely-different-secret')
        with other_app.app_context():
            import auth
            foreign_token = auth.generate_token(user_id=99, username='eve')

        with self.app.app_context():
            import auth
            result = auth.verify_token(foreign_token)
            self.assertIsNone(result)

    def test_generate_token_raises_without_secret(self):
        """generate_token raises RuntimeError when JWT_SECRET_KEY is not configured."""
        app = _make_app(None)
        with app.app_context():
            import auth
            with self.assertRaises(RuntimeError):
                auth.generate_token(user_id=1, username='nokey')


# ---------------------------------------------------------------------------
# 4. Regression: the known weak literal must not appear in the source.
# ---------------------------------------------------------------------------

class TestNoKnownWeakSecretInSource(unittest.TestCase):
    """Confirm the original hardcoded value is gone from config.py."""

    def test_known_weak_secret_not_in_config_source(self):
        """The literal 'secret_key_12345' must not appear in config.py."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config.py'
        )
        with open(config_path, 'r') as fh:
            source = fh.read()
        self.assertNotIn(
            'secret_key_12345',
            source,
            "The hardcoded secret 'secret_key_12345' must not appear in config.py."
        )


if __name__ == '__main__':
    unittest.main()
