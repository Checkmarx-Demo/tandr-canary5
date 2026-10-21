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


class TestConfigNoHardcodedSecrets(unittest.TestCase):
    """Tests verifying that Config class does not contain hardcoded secrets (CWE-798)."""

    def setUp(self):
        from config import Config
        self.Config = Config

    def test_admin_password_not_hardcoded(self):
        """ADMIN_PASSWORD must come from env var, not be a hardcoded literal."""
        import inspect, ast, textwrap

        source_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config.py',
        )
        with open(source_path) as f:
            tree = ast.parse(f.read())

        # Walk the AST looking for `ADMIN_PASSWORD = <literal string>`
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == 'Config':
                for item in ast.walk(node):
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name) and target.id == 'ADMIN_PASSWORD':
                                # The value must NOT be a string constant
                                self.assertNotIsInstance(
                                    item.value,
                                    ast.Constant,
                                    "ADMIN_PASSWORD must not be assigned a hardcoded string literal in Config",
                                )

    def test_jwt_secret_key_not_hardcoded(self):
        """JWT_SECRET_KEY must come from env var, not be a hardcoded literal."""
        import ast

        source_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config.py',
        )
        with open(source_path) as f:
            tree = ast.parse(f.read())

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == 'Config':
                for item in ast.walk(node):
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name) and target.id == 'JWT_SECRET_KEY':
                                self.assertNotIsInstance(
                                    item.value,
                                    ast.Constant,
                                    "JWT_SECRET_KEY must not be assigned a hardcoded string literal in Config",
                                )

    def test_aws_secret_access_key_not_hardcoded(self):
        """AWS_SECRET_ACCESS_KEY must come from env var, not be a hardcoded literal."""
        import ast

        source_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config.py',
        )
        with open(source_path) as f:
            tree = ast.parse(f.read())

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == 'Config':
                for item in ast.walk(node):
                    if isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name) and target.id == 'AWS_SECRET_ACCESS_KEY':
                                self.assertNotIsInstance(
                                    item.value,
                                    ast.Constant,
                                    "AWS_SECRET_ACCESS_KEY must not be assigned a hardcoded string literal in Config",
                                )

    def test_admin_password_reads_from_env(self):
        """Config.ADMIN_PASSWORD reads value from ADMIN_PASSWORD environment variable."""
        test_password = 'env-supplied-test-password'
        original = os.environ.pop('ADMIN_PASSWORD', None)
        try:
            os.environ['ADMIN_PASSWORD'] = test_password
            # Re-import to pick up env value (class-level assignment)
            import importlib
            import config as config_module
            importlib.reload(config_module)
            self.assertEqual(config_module.Config.ADMIN_PASSWORD, test_password)
        finally:
            if original is None:
                os.environ.pop('ADMIN_PASSWORD', None)
            else:
                os.environ['ADMIN_PASSWORD'] = original
            # Reload to restore original state
            import importlib
            import config as config_module
            importlib.reload(config_module)

    def test_admin_password_none_when_env_unset(self):
        """Config.ADMIN_PASSWORD is None when environment variable is not set."""
        original = os.environ.pop('ADMIN_PASSWORD', None)
        try:
            import importlib
            import config as config_module
            importlib.reload(config_module)
            self.assertIsNone(config_module.Config.ADMIN_PASSWORD)
        finally:
            if original is not None:
                os.environ['ADMIN_PASSWORD'] = original
            import importlib
            import config as config_module
            importlib.reload(config_module)

    def test_no_known_default_credentials_in_config_source(self):
        """Config source must not contain well-known default passwords as string literals."""
        known_bad = ['admin123', 'password123', 'secret_key_12345',
                     'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY']
        source_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'config.py',
        )
        with open(source_path) as f:
            source = f.read()

        for bad_value in known_bad:
            self.assertNotIn(
                bad_value,
                source,
                f"Hardcoded secret '{bad_value}' found in config.py",
            )


if __name__ == '__main__':
    unittest.main()

