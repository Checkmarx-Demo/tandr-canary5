"""
Basic tests for Flask application configuration and imports
Note: Full app tests require proper environment setup
"""
import importlib
import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAppConfiguration(unittest.TestCase):
    """Test basic application configuration"""

    # ---------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------

    def _reload_config(self):
        """Force a fresh import of the config module so env-var changes take effect."""
        import config as _cfg_mod
        importlib.reload(_cfg_mod)
        return _cfg_mod.Config

    # ---------------------------------------------------------------------------
    # JWT_SECRET_KEY is read from the environment (CWE-798 regression guard)
    # ---------------------------------------------------------------------------

    def test_jwt_secret_key_read_from_environment(self):
        """JWT_SECRET_KEY must come from the environment, not a hardcoded literal."""
        sentinel = 'env-supplied-secret-for-test-abc123'
        old_val = os.environ.get('JWT_SECRET_KEY')
        try:
            os.environ['JWT_SECRET_KEY'] = sentinel
            Config = self._reload_config()
            self.assertEqual(
                Config.JWT_SECRET_KEY,
                sentinel,
                "Config.JWT_SECRET_KEY must equal the value set in JWT_SECRET_KEY env var.",
            )
        finally:
            if old_val is None:
                os.environ.pop('JWT_SECRET_KEY', None)
            else:
                os.environ['JWT_SECRET_KEY'] = old_val
            self._reload_config()

    def test_jwt_secret_key_not_hardcoded(self):
        """JWT_SECRET_KEY must NOT be the old hardcoded value 'secret_key_12345'."""
        sentinel = 'safe-test-secret-xyz987'
        old_val = os.environ.get('JWT_SECRET_KEY')
        try:
            os.environ['JWT_SECRET_KEY'] = sentinel
            Config = self._reload_config()
            self.assertNotEqual(
                Config.JWT_SECRET_KEY,
                'secret_key_12345',
                "The hardcoded secret 'secret_key_12345' must not be used.",
            )
        finally:
            if old_val is None:
                os.environ.pop('JWT_SECRET_KEY', None)
            else:
                os.environ['JWT_SECRET_KEY'] = old_val
            self._reload_config()

    def test_jwt_secret_key_missing_env_raises(self):
        """Config must raise KeyError when JWT_SECRET_KEY env var is absent."""
        old_val = os.environ.pop('JWT_SECRET_KEY', None)
        try:
            with self.assertRaises(KeyError):
                self._reload_config()
        finally:
            if old_val is not None:
                os.environ['JWT_SECRET_KEY'] = old_val
            self._reload_config()

    def test_aws_credentials_not_hardcoded(self):
        """AWS_ACCESS_KEY_ID must not contain the example placeholder key."""
        old_jwt = os.environ.get('JWT_SECRET_KEY')
        old_aws = os.environ.get('AWS_ACCESS_KEY_ID')
        try:
            os.environ['JWT_SECRET_KEY'] = 'test-jwt-secret'
            os.environ.pop('AWS_ACCESS_KEY_ID', None)
            Config = self._reload_config()
            self.assertIsNone(
                Config.AWS_ACCESS_KEY_ID,
                "AWS_ACCESS_KEY_ID should default to None when env var is unset.",
            )
            self.assertNotEqual(
                Config.AWS_ACCESS_KEY_ID,
                'AKIAIOSFODNN7EXAMPLE',
                "Example AWS key must not be hardcoded.",
            )
        finally:
            if old_jwt is None:
                os.environ.pop('JWT_SECRET_KEY', None)
            else:
                os.environ['JWT_SECRET_KEY'] = old_jwt
            if old_aws is not None:
                os.environ['AWS_ACCESS_KEY_ID'] = old_aws
            self._reload_config()

    def test_no_hardcoded_secrets_in_source(self):
        """Verify that known hardcoded secret strings are absent from config.py source."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config.py',
        )
        with open(config_path) as fh:
            source = fh.read()
        forbidden = [
            'secret_key_12345',
            'AKIAIOSFODNN7EXAMPLE',
            'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'admin123',
        ]
        for secret in forbidden:
            self.assertNotIn(
                secret,
                source,
                f"Hardcoded secret fragment '{secret}' must not appear in config.py.",
            )

    # ---------------------------------------------------------------------------
    # Original import tests (preserved)
    # ---------------------------------------------------------------------------

    def test_config_import(self):
        """Test that config module can be imported"""
        old_val = os.environ.get('JWT_SECRET_KEY')
        try:
            os.environ['JWT_SECRET_KEY'] = 'test-secret-for-import'
            Config = self._reload_config()
            self.assertIsNotNone(Config)
            self.assertTrue(hasattr(Config, 'JWT_SECRET_KEY'))
            self.assertTrue(hasattr(Config, 'DATABASE_URL'))
        except ImportError as e:
            self.fail(f"Failed to import Config: {e}")
        finally:
            if old_val is None:
                os.environ.pop('JWT_SECRET_KEY', None)
            else:
                os.environ['JWT_SECRET_KEY'] = old_val
            self._reload_config()
    
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


if __name__ == '__main__':
    unittest.main()

