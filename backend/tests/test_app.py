"""
Basic tests for Flask application configuration and imports
Note: Full app tests require proper environment setup
"""
import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAppConfiguration(unittest.TestCase):
    """Test basic application configuration"""
    
    def test_config_import(self):
        """Test that config module can be imported"""
        try:
            from config import Config
            self.assertIsNotNone(Config)
            self.assertTrue(hasattr(Config, 'JWT_SECRET_KEY'))
            self.assertTrue(hasattr(Config, 'DATABASE_URL'))
        except ImportError as e:
            self.fail(f"Failed to import Config: {e}")
    
    def test_models_import(self):
        """Test that models can be imported"""
        try:
            from models import User, Project, Task, Message
            self.assertIsNotNone(User)
            self.assertIsNotNone(Project)
            self.assertIsNotNone(Task)
            self.assertIsNotNone(Message)
        except ImportError as e:
            self.fail(f"Failed to import models: {e}")
    
    def test_database_import(self):
        """Test that database module can be imported"""
        try:
            from database import init_db
            self.assertIsNotNone(init_db)
        except ImportError as e:
            self.fail(f"Failed to import database: {e}")


class TestRouteImports(unittest.TestCase):
    """Test that route modules can be imported"""
    
    def test_auth_routes_import(self):
        """Test auth routes import"""
        try:
            from routes import auth
            self.assertIsNotNone(auth)
            self.assertTrue(hasattr(auth, 'bp'))
        except ImportError as e:
            self.fail(f"Failed to import auth routes: {e}")
    
    def test_projects_routes_import(self):
        """Test projects routes import"""
        try:
            from routes import projects
            self.assertIsNotNone(projects)
            self.assertTrue(hasattr(projects, 'bp'))
        except ImportError as e:
            self.fail(f"Failed to import projects routes: {e}")
    
    def test_tasks_routes_import(self):
        """Test tasks routes import"""
        try:
            from routes import tasks
            self.assertIsNotNone(tasks)
            self.assertTrue(hasattr(tasks, 'bp'))
        except ImportError as e:
            self.fail(f"Failed to import tasks routes: {e}")


class TestConfigNoHardcodedCredentials(unittest.TestCase):
    """Security regression tests: ensure credentials are never hardcoded in Config.

    These tests verify CWE-798 (Use of Hard-coded Credentials) does not regress.
    Each sensitive attribute must be None (not set) when its environment variable
    is absent, confirming the value can only enter the application via the
    environment.
    """

    # Known-bad values that were previously hardcoded — they must never appear
    # in the Config class attributes.
    _FORBIDDEN_VALUES = {
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # old AWS secret
        "AKIAIOSFODNN7EXAMPLE",                          # old AWS key ID
        "secret_key_12345",                              # old JWT secret
        "admin123",                                      # old admin password
        "password123",                                   # old DB password fragment
    }

    def _get_config_without_env(self, monkeypatched_environ):
        """Import a fresh Config class with the given environment."""
        import importlib
        import config as cfg_module
        # Reload to pick up the patched os.environ
        importlib.reload(cfg_module)
        return cfg_module.Config

    def setUp(self):
        """Snapshot the real environment and clear sensitive keys."""
        self._orig_env = {
            k: os.environ.pop(k)
            for k in (
                'AWS_SECRET_ACCESS_KEY',
                'AWS_ACCESS_KEY_ID',
                'JWT_SECRET_KEY',
                'JWT_SECRET',
                'ADMIN_PASSWORD',
                'DATABASE_URL',
            )
            if k in os.environ
        }

    def tearDown(self):
        """Restore original environment and reload config to original state."""
        os.environ.update(self._orig_env)
        import importlib, config as cfg_module
        importlib.reload(cfg_module)

    def _fresh_config(self):
        import importlib, config as cfg_module
        importlib.reload(cfg_module)
        return cfg_module.Config

    # ------------------------------------------------------------------
    # AWS_SECRET_ACCESS_KEY
    # ------------------------------------------------------------------
    def test_aws_secret_not_hardcoded_when_env_absent(self):
        """AWS_SECRET_ACCESS_KEY must be None when env var is not set."""
        cfg = self._fresh_config()
        self.assertIsNone(
            cfg.AWS_SECRET_ACCESS_KEY,
            "AWS_SECRET_ACCESS_KEY must not have a hardcoded fallback value.",
        )

    def test_aws_secret_read_from_env(self):
        """AWS_SECRET_ACCESS_KEY must reflect the environment variable."""
        os.environ['AWS_SECRET_ACCESS_KEY'] = 'env-test-secret-key'
        cfg = self._fresh_config()
        self.assertEqual(cfg.AWS_SECRET_ACCESS_KEY, 'env-test-secret-key')

    def test_aws_secret_no_forbidden_value(self):
        """AWS_SECRET_ACCESS_KEY must not contain any previously hardcoded value."""
        cfg = self._fresh_config()
        if cfg.AWS_SECRET_ACCESS_KEY is not None:
            self.assertNotIn(cfg.AWS_SECRET_ACCESS_KEY, self._FORBIDDEN_VALUES)

    # ------------------------------------------------------------------
    # AWS_ACCESS_KEY_ID
    # ------------------------------------------------------------------
    def test_aws_key_id_not_hardcoded_when_env_absent(self):
        """AWS_ACCESS_KEY_ID must be None when env var is not set."""
        cfg = self._fresh_config()
        self.assertIsNone(
            cfg.AWS_ACCESS_KEY_ID,
            "AWS_ACCESS_KEY_ID must not have a hardcoded fallback value.",
        )

    def test_aws_key_id_read_from_env(self):
        """AWS_ACCESS_KEY_ID must reflect the environment variable."""
        os.environ['AWS_ACCESS_KEY_ID'] = 'AKIATESTEXAMPLE00001'
        cfg = self._fresh_config()
        self.assertEqual(cfg.AWS_ACCESS_KEY_ID, 'AKIATESTEXAMPLE00001')

    def test_aws_key_id_no_forbidden_value(self):
        """AWS_ACCESS_KEY_ID must not contain any previously hardcoded value."""
        cfg = self._fresh_config()
        if cfg.AWS_ACCESS_KEY_ID is not None:
            self.assertNotIn(cfg.AWS_ACCESS_KEY_ID, self._FORBIDDEN_VALUES)

    # ------------------------------------------------------------------
    # JWT_SECRET_KEY
    # ------------------------------------------------------------------
    def test_jwt_secret_not_hardcoded_when_env_absent(self):
        """JWT_SECRET_KEY must be None when env vars are not set."""
        cfg = self._fresh_config()
        self.assertIsNone(
            cfg.JWT_SECRET_KEY,
            "JWT_SECRET_KEY must not have a hardcoded fallback value.",
        )

    def test_jwt_secret_read_from_env_jwt_secret_key(self):
        """JWT_SECRET_KEY must be read from JWT_SECRET_KEY env var."""
        os.environ['JWT_SECRET_KEY'] = 'env-jwt-secret-key'
        cfg = self._fresh_config()
        self.assertEqual(cfg.JWT_SECRET_KEY, 'env-jwt-secret-key')

    def test_jwt_secret_read_from_env_jwt_secret_fallback(self):
        """JWT_SECRET_KEY must fall back to JWT_SECRET env var."""
        os.environ['JWT_SECRET'] = 'env-jwt-secret-fallback'
        cfg = self._fresh_config()
        self.assertEqual(cfg.JWT_SECRET_KEY, 'env-jwt-secret-fallback')

    def test_jwt_secret_no_forbidden_value(self):
        """JWT_SECRET_KEY must not contain any previously hardcoded value."""
        cfg = self._fresh_config()
        if cfg.JWT_SECRET_KEY is not None:
            self.assertNotIn(cfg.JWT_SECRET_KEY, self._FORBIDDEN_VALUES)

    # ------------------------------------------------------------------
    # ADMIN_PASSWORD
    # ------------------------------------------------------------------
    def test_admin_password_not_hardcoded_when_env_absent(self):
        """ADMIN_PASSWORD must be None when env var is not set."""
        cfg = self._fresh_config()
        self.assertIsNone(
            cfg.ADMIN_PASSWORD,
            "ADMIN_PASSWORD must not have a hardcoded fallback value.",
        )

    def test_admin_password_read_from_env(self):
        """ADMIN_PASSWORD must reflect the environment variable."""
        os.environ['ADMIN_PASSWORD'] = 'env-admin-password-secure'
        cfg = self._fresh_config()
        self.assertEqual(cfg.ADMIN_PASSWORD, 'env-admin-password-secure')

    def test_admin_password_no_forbidden_value(self):
        """ADMIN_PASSWORD must not contain any previously hardcoded value."""
        cfg = self._fresh_config()
        if cfg.ADMIN_PASSWORD is not None:
            self.assertNotIn(cfg.ADMIN_PASSWORD, self._FORBIDDEN_VALUES)

    # ------------------------------------------------------------------
    # DATABASE_URL
    # ------------------------------------------------------------------
    def test_database_url_not_hardcoded_when_env_absent(self):
        """DATABASE_URL must be None when env var is not set (no fallback)."""
        cfg = self._fresh_config()
        self.assertIsNone(
            cfg.DATABASE_URL,
            "DATABASE_URL must not fall back to a hardcoded connection string.",
        )

    def test_database_url_no_embedded_password(self):
        """DATABASE_URL class attribute must not contain 'password123'."""
        cfg = self._fresh_config()
        db_url = cfg.DATABASE_URL or ''
        self.assertNotIn(
            'password123', db_url,
            "DATABASE_URL must not contain a hardcoded password.",
        )

    # ------------------------------------------------------------------
    # Source-code level check (belt-and-suspenders)
    # ------------------------------------------------------------------
    def test_config_source_contains_no_hardcoded_secrets(self):
        """config.py source must not contain any known hardcoded secret string."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config.py',
        )
        with open(config_path, 'r') as fh:
            source = fh.read()
        for forbidden in self._FORBIDDEN_VALUES:
            self.assertNotIn(
                forbidden,
                source,
                f"config.py source must not contain the hardcoded value: {forbidden!r}",
            )


if __name__ == '__main__':
    unittest.main()

