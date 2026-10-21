"""
Basic tests for Flask application configuration and imports
Note: Full app tests require proper environment setup
"""
import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Known AWS key patterns and other hardcoded-secret signatures that must NOT
# appear as literal defaults in the Config class.
_HARDCODED_AWS_KEY_PATTERNS = [
    "AKIAIOSFODNN7EXAMPLE",  # example key from SAST finding
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # example secret from SAST finding
]
_HARDCODED_CREDENTIAL_PATTERNS = [
    "secret_key_12345",    # former JWT_SECRET_KEY literal
    "password123",         # former DB / admin password literal
    "admin123",            # former ADMIN_PASSWORD literal
]


class TestConfigNoHardcodedCredentials(unittest.TestCase):
    """
    Security regression tests: verify that Config no longer contains
    hardcoded AWS credentials or other secrets (CWE-798).
    """

    def setUp(self):
        """Import Config fresh for each test."""
        from config import Config
        self.Config = Config

    # ------------------------------------------------------------------
    # AWS credentials must come exclusively from environment variables
    # ------------------------------------------------------------------

    def test_aws_access_key_id_not_hardcoded(self):
        """AWS_ACCESS_KEY_ID must not be a hardcoded literal value."""
        for pattern in _HARDCODED_AWS_KEY_PATTERNS:
            self.assertNotEqual(
                self.Config.AWS_ACCESS_KEY_ID,
                pattern,
                f"AWS_ACCESS_KEY_ID must not be hardcoded to '{pattern}'",
            )

    def test_aws_secret_access_key_not_hardcoded(self):
        """AWS_SECRET_ACCESS_KEY must not be a hardcoded literal value."""
        for pattern in _HARDCODED_AWS_KEY_PATTERNS:
            self.assertNotEqual(
                self.Config.AWS_SECRET_ACCESS_KEY,
                pattern,
                f"AWS_SECRET_ACCESS_KEY must not be hardcoded to '{pattern}'",
            )

    def test_aws_access_key_id_reads_from_env(self):
        """AWS_ACCESS_KEY_ID value must originate from the environment."""
        import importlib
        import config as config_module
        test_key = "TEST_KEY_FROM_ENV_VAR"
        original = os.environ.pop("AWS_ACCESS_KEY_ID", None)
        try:
            os.environ["AWS_ACCESS_KEY_ID"] = test_key
            # Reload the module so class-level os.environ.get() re-evaluates
            importlib.reload(config_module)
            self.assertEqual(
                config_module.Config.AWS_ACCESS_KEY_ID,
                test_key,
                "AWS_ACCESS_KEY_ID should reflect the AWS_ACCESS_KEY_ID env var",
            )
        finally:
            if original is None:
                os.environ.pop("AWS_ACCESS_KEY_ID", None)
            else:
                os.environ["AWS_ACCESS_KEY_ID"] = original
            importlib.reload(config_module)

    def test_aws_secret_access_key_reads_from_env(self):
        """AWS_SECRET_ACCESS_KEY value must originate from the environment."""
        import importlib
        import config as config_module
        test_secret = "TEST_SECRET_FROM_ENV_VAR"
        original = os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
        try:
            os.environ["AWS_SECRET_ACCESS_KEY"] = test_secret
            importlib.reload(config_module)
            self.assertEqual(
                config_module.Config.AWS_SECRET_ACCESS_KEY,
                test_secret,
                "AWS_SECRET_ACCESS_KEY should reflect the AWS_SECRET_ACCESS_KEY env var",
            )
        finally:
            if original is None:
                os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
            else:
                os.environ["AWS_SECRET_ACCESS_KEY"] = original
            importlib.reload(config_module)

    def test_aws_access_key_id_is_none_when_env_unset(self):
        """When AWS_ACCESS_KEY_ID env var is absent, Config.AWS_ACCESS_KEY_ID must be None."""
        import importlib
        import config as config_module
        original = os.environ.pop("AWS_ACCESS_KEY_ID", None)
        try:
            importlib.reload(config_module)
            self.assertIsNone(
                config_module.Config.AWS_ACCESS_KEY_ID,
                "AWS_ACCESS_KEY_ID must default to None when the env var is not set",
            )
        finally:
            if original is not None:
                os.environ["AWS_ACCESS_KEY_ID"] = original
            importlib.reload(config_module)

    def test_aws_secret_access_key_is_none_when_env_unset(self):
        """When AWS_SECRET_ACCESS_KEY env var is absent, Config.AWS_SECRET_ACCESS_KEY must be None."""
        import importlib
        import config as config_module
        original = os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
        try:
            importlib.reload(config_module)
            self.assertIsNone(
                config_module.Config.AWS_SECRET_ACCESS_KEY,
                "AWS_SECRET_ACCESS_KEY must default to None when the env var is not set",
            )
        finally:
            if original is not None:
                os.environ["AWS_SECRET_ACCESS_KEY"] = original
            importlib.reload(config_module)

    # ------------------------------------------------------------------
    # No other previously-hardcoded credentials must be present either
    # ------------------------------------------------------------------

    def test_jwt_secret_key_not_hardcoded(self):
        """JWT_SECRET_KEY must not contain the old hardcoded literal."""
        for pattern in _HARDCODED_CREDENTIAL_PATTERNS:
            self.assertNotEqual(
                self.Config.JWT_SECRET_KEY,
                pattern,
                f"JWT_SECRET_KEY must not be hardcoded to '{pattern}'",
            )

    def test_admin_password_not_hardcoded(self):
        """ADMIN_PASSWORD must not contain the old hardcoded literal."""
        for pattern in _HARDCODED_CREDENTIAL_PATTERNS:
            self.assertNotEqual(
                self.Config.ADMIN_PASSWORD,
                pattern,
                f"ADMIN_PASSWORD must not be hardcoded to '{pattern}'",
            )

    def test_config_source_file_contains_no_hardcoded_aws_key(self):
        """
        Source-level check: the config.py file itself must not contain
        the known example AWS key strings as literal values.
        """
        import config as config_module
        config_path = os.path.abspath(config_module.__file__)
        # Handle compiled .pyc fallback
        if config_path.endswith(".pyc"):
            config_path = config_path[:-1]
        with open(config_path, "r", encoding="utf-8") as fh:
            source = fh.read()
        for pattern in _HARDCODED_AWS_KEY_PATTERNS:
            self.assertNotIn(
                pattern,
                source,
                f"config.py source must not contain hardcoded AWS credential '{pattern}'",
            )

    def test_config_source_file_contains_no_hardcoded_passwords(self):
        """
        Source-level check: the config.py file itself must not contain
        the known example password strings as literal values.
        """
        import config as config_module
        config_path = os.path.abspath(config_module.__file__)
        if config_path.endswith(".pyc"):
            config_path = config_path[:-1]
        with open(config_path, "r", encoding="utf-8") as fh:
            source = fh.read()
        for pattern in _HARDCODED_CREDENTIAL_PATTERNS:
            self.assertNotIn(
                pattern,
                source,
                f"config.py source must not contain hardcoded credential '{pattern}'",
            )


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


if __name__ == '__main__':
    unittest.main()

