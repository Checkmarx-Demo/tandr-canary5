"""
Basic tests for Flask application configuration and imports
Note: Full app tests require proper environment setup
"""
import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Provide required environment variables before importing config
os.environ.setdefault('JWT_SECRET_KEY', 'test-secret-key-for-unit-testing-only')
os.environ.setdefault('DATABASE_URL', 'sqlite:///:memory:')
os.environ.setdefault('ADMIN_PASSWORD', 'test-admin-password-only')


class TestHardcodedCredentialsRemediation(unittest.TestCase):
    """Tests verifying that hardcoded credentials have been removed from config.py."""

    # Known plaintext secrets that must not appear in the Config class
    _FORBIDDEN_LITERALS = [
        "secret_key_12345",
        "password123",
        "admin123",
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ]

    def _read_config_source(self) -> str:
        """Return the raw source text of config.py for static checks."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config.py",
        )
        with open(config_path, "r") as fh:
            return fh.read()

    def test_no_hardcoded_database_password_in_source(self):
        """DATABASE_URL must not contain a hardcoded password in the source file."""
        source = self._read_config_source()
        self.assertNotIn(
            "password123",
            source,
            "Hardcoded database password 'password123' found in config.py",
        )

    def test_no_hardcoded_jwt_secret_in_source(self):
        """JWT_SECRET_KEY must not be a literal string in the source file."""
        source = self._read_config_source()
        self.assertNotIn(
            "secret_key_12345",
            source,
            "Hardcoded JWT secret 'secret_key_12345' found in config.py",
        )

    def test_no_hardcoded_aws_keys_in_source(self):
        """AWS credentials must not be literal strings in the source file."""
        source = self._read_config_source()
        self.assertNotIn(
            "AKIAIOSFODNN7EXAMPLE",
            source,
            "Hardcoded AWS access key found in config.py",
        )
        self.assertNotIn(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            source,
            "Hardcoded AWS secret key found in config.py",
        )

    def test_no_hardcoded_admin_password_in_source(self):
        """ADMIN_PASSWORD must not be a literal string in the source file."""
        source = self._read_config_source()
        self.assertNotIn(
            "admin123",
            source,
            "Hardcoded admin password 'admin123' found in config.py",
        )

    def test_database_url_loaded_from_environment(self):
        """Config.DATABASE_URL must equal the value of the DATABASE_URL env var."""
        expected = os.environ.get('DATABASE_URL')
        from config import Config
        self.assertEqual(
            Config.DATABASE_URL,
            expected,
            "Config.DATABASE_URL does not match the DATABASE_URL environment variable",
        )

    def test_jwt_secret_loaded_from_environment(self):
        """Config.JWT_SECRET_KEY must equal the value of the JWT_SECRET_KEY env var."""
        expected = os.environ.get('JWT_SECRET_KEY')
        from config import Config
        self.assertEqual(
            Config.JWT_SECRET_KEY,
            expected,
            "Config.JWT_SECRET_KEY does not match the JWT_SECRET_KEY environment variable",
        )

    def test_missing_database_url_raises_error(self):
        """Config class must raise EnvironmentError when DATABASE_URL is unset."""
        import importlib
        import config as config_module

        original_url = os.environ.pop('DATABASE_URL', None)
        original_key = os.environ.pop('JWT_SECRET_KEY', None)
        original_pw = os.environ.pop('ADMIN_PASSWORD', None)
        try:
            with self.assertRaises(EnvironmentError):
                importlib.reload(config_module)
        finally:
            # Restore environment so subsequent tests are unaffected
            if original_url is not None:
                os.environ['DATABASE_URL'] = original_url
            if original_key is not None:
                os.environ['JWT_SECRET_KEY'] = original_key
            if original_pw is not None:
                os.environ['ADMIN_PASSWORD'] = original_pw
            importlib.reload(config_module)

    def test_missing_jwt_secret_raises_error(self):
        """Config class must raise EnvironmentError when JWT_SECRET_KEY is unset."""
        import importlib
        import config as config_module

        original_url = os.environ.get('DATABASE_URL')
        original_key = os.environ.pop('JWT_SECRET_KEY', None)
        original_pw = os.environ.get('ADMIN_PASSWORD')
        try:
            with self.assertRaises(EnvironmentError):
                importlib.reload(config_module)
        finally:
            if original_key is not None:
                os.environ['JWT_SECRET_KEY'] = original_key
            if original_url is not None:
                os.environ['DATABASE_URL'] = original_url
            if original_pw is not None:
                os.environ['ADMIN_PASSWORD'] = original_pw
            importlib.reload(config_module)


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

