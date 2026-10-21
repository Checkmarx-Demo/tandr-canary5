"""
Security regression tests for CWE-798 (Use of Hard-coded Credentials) in database.py.

These tests verify that seed_data() no longer uses predictable, hard-coded passwords
(e.g., the username itself) when creating test users.  Passwords must either come from
the SEED_USER_PASSWORD environment variable or be generated randomly per-user.
"""
import unittest
import sys
import os

# Add parent directory to path so we can import backend modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
from flask import Flask
from models import db, User
from config import Config


class TestConfig(Config):
    """Minimal in-memory configuration used by all tests in this file."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    JWT_SECRET_KEY = 'test-only-secret-key'
    UPLOAD_FOLDER = '/tmp/test_uploads'
    LOG_FILE = '/tmp/test.log'


def _make_app():
    """Return a minimal Flask app with an in-memory SQLite DB."""
    app = Flask(__name__)
    app.config.from_object(TestConfig)
    db.init_app(app)
    return app


class TestSeedDataNoHardcodedPasswords(unittest.TestCase):
    """Verify that seed_data() never assigns predictable hard-coded passwords."""

    def setUp(self):
        self.app = _make_app()
        with self.app.app_context():
            db.create_all()
            # Pre-create the Admin user that seed_data() requires
            admin = User(username='Admin', email='admin@projecthub.com', role='admin')
            admin.set_password('someAdminPassword')
            db.session.add(admin)
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def _get_seeded_users(self):
        """Run seed_data and return the non-admin User objects it created."""
        from database import seed_data
        seed_data(self.app)
        with self.app.app_context():
            return User.query.filter(User.username != 'Admin').all()

    def test_password_is_not_same_as_username(self):
        """
        CWE-798 regression: seeded user passwords must not equal their username.
        Previously the code did `password = user_info['username']` which allowed
        authentication with the plaintext username as a password.
        """
        # Clear SEED_USER_PASSWORD to test the random-generation path
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SEED_USER_PASSWORD', None)
            users = self._get_seeded_users()

        self.assertGreater(len(users), 0, "seed_data() must create at least one test user")

        for user in users:
            # The password hash must NOT match the username used as a password
            password_matches_username = user.check_password(user.username)
            self.assertFalse(
                password_matches_username,
                f"User '{user.username}' has its own username as password — "
                "this is a hard-coded credential (CWE-798)."
            )

    def test_password_is_not_capitalised_username(self):
        """
        Additional check: password must not be the capitalised or lowercased username,
        which were common variants of the old hard-coded scheme.
        """
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SEED_USER_PASSWORD', None)
            users = self._get_seeded_users()

        for user in users:
            self.assertFalse(
                user.check_password(user.username.lower()),
                f"User '{user.username}': password equals username.lower()."
            )
            self.assertFalse(
                user.check_password(user.username.upper()),
                f"User '{user.username}': password equals username.upper()."
            )

    def test_env_var_password_is_used_when_set(self):
        """
        When SEED_USER_PASSWORD is set, seeded users should authenticate with that value
        (verifying the env-var path works correctly).
        """
        test_password = 'Env$ecureP@ss!99'
        with patch.dict(os.environ, {'SEED_USER_PASSWORD': test_password}):
            users = self._get_seeded_users()

        self.assertGreater(len(users), 0)
        for user in users:
            self.assertTrue(
                user.check_password(test_password),
                f"User '{user.username}' should authenticate with SEED_USER_PASSWORD."
            )

    def test_random_passwords_differ_between_users(self):
        """
        When no SEED_USER_PASSWORD is set, each user should receive a distinct
        random password (not a shared hard-coded constant).
        """
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SEED_USER_PASSWORD', None)
            users = self._get_seeded_users()

        if len(users) < 2:
            self.skipTest("Need at least 2 seeded users to compare password hashes.")

        hashes = [user.password_hash for user in users]
        unique_hashes = set(hashes)
        self.assertEqual(
            len(unique_hashes), len(hashes),
            "All seeded users should have distinct password hashes when SEED_USER_PASSWORD is unset."
        )

    def test_api_key_is_not_derived_from_predictable_password(self):
        """
        Previously api_key was computed as:
            f"{username}_api_key_{md5(password)}"
        where password == username — making the api_key fully predictable.
        After the fix the api_key must use random bytes, so it cannot be
        reconstructed by knowing only the username.
        """
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('SEED_USER_PASSWORD', None)
            users = self._get_seeded_users()

        import hashlib
        for user in users:
            # Reconstruct what the old predictable api_key would have been
            old_predictable_key = (
                f"{user.username}_api_key_{hashlib.md5(user.username.encode()).hexdigest()}"
            )
            self.assertNotEqual(
                user.api_key,
                old_predictable_key,
                f"User '{user.username}' api_key matches the old predictable value — "
                "it must use random entropy instead."
            )

    def test_seed_skips_when_skip_seed_env_set(self):
        """seed_data() must respect the SKIP_SEED=true environment variable."""
        with patch.dict(os.environ, {'SKIP_SEED': 'true'}):
            from database import seed_data
            # Only the Admin pre-created in setUp should exist
            seed_data(self.app)
            with self.app.app_context():
                count = User.query.count()
            self.assertEqual(count, 1, "No additional users should be created when SKIP_SEED=true.")


class TestSeedDataPasswordSource(unittest.TestCase):
    """Unit-level tests that mock the DB to focus solely on credential handling logic."""

    def test_secrets_module_used_for_random_password(self):
        """
        Verify the 'secrets' module is imported in database.py — a static
        guarantee that cryptographically random passwords are available.
        """
        import database
        import secrets as _secrets
        self.assertIs(
            getattr(database, 'secrets', None),
            _secrets,
            "database.py must import the 'secrets' module for secure password generation."
        )

    def test_no_hardcoded_password_constant_in_source(self):
        """
        Regression guard: the source file must not contain the pattern
        `password = user_info['username']` which was the original hard-coded credential.
        """
        src_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'database.py'
        )
        with open(src_path, 'r') as fh:
            source = fh.read()

        self.assertNotIn(
            "password = user_info['username']",
            source,
            "Hard-coded credential pattern found in database.py — CWE-798 not remediated."
        )

    def test_seed_user_password_env_var_referenced_in_source(self):
        """
        The fix must read SEED_USER_PASSWORD from the environment rather than
        hard-coding a value.
        """
        src_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'database.py'
        )
        with open(src_path, 'r') as fh:
            source = fh.read()

        self.assertIn(
            'SEED_USER_PASSWORD',
            source,
            "database.py must read passwords from the SEED_USER_PASSWORD environment variable."
        )


if __name__ == '__main__':
    unittest.main()
