"""
Basic tests for database models
"""
import unittest
import os
from unittest.mock import patch, MagicMock
from datetime import datetime
from models import User, Project, Task, Message


class TestUserModel(unittest.TestCase):
    """Test User model"""
    
    def test_user_password_hashing(self):
        """Test password hashing and checking"""
        user = User()
        user.username = "testuser"
        user.email = "test@example.com"
        user.set_password("password123")
        
        # Password should be hashed
        self.assertNotEqual(user.password_hash, "password123")
        
        # Check password should work
        self.assertTrue(user.check_password("password123"))
        self.assertFalse(user.check_password("wrongpassword"))
    
    def test_user_to_dict(self):
        """Test user serialization"""
        user = User()
        user.id = 1
        user.username = "testuser"
        user.email = "test@example.com"
        user.role = "team_member"
        user.created_at = datetime.now()
        
        user_dict = user.to_dict()
        
        self.assertEqual(user_dict['id'], 1)
        self.assertEqual(user_dict['username'], "testuser")
        self.assertEqual(user_dict['email'], "test@example.com")
        self.assertEqual(user_dict['role'], "team_member")
        self.assertIn('created_at', user_dict)


class TestProjectModel(unittest.TestCase):
    """Test Project model"""
    
    def test_project_to_dict(self):
        """Test project serialization"""
        project = Project()
        project.id = 1
        project.name = "Test Project"
        project.description = "A test project"
        project.owner_id = 1
        project.is_public = False
        project.created_at = datetime.now()
        project.updated_at = datetime.now()
        
        project_dict = project.to_dict()
        
        self.assertEqual(project_dict['id'], 1)
        self.assertEqual(project_dict['name'], "Test Project")
        self.assertEqual(project_dict['description'], "A test project")
        self.assertEqual(project_dict['owner_id'], 1)
        self.assertFalse(project_dict['is_public'])


class TestTaskModel(unittest.TestCase):
    """Test Task model"""
    
    def test_task_to_dict(self):
        """Test task serialization"""
        task = Task()
        task.id = 1
        task.title = "Test Task"
        task.description = "A test task"
        task.project_id = 1
        task.created_by = 1
        task.status = "pending"
        task.priority = "high"
        task.created_at = datetime.now()
        
        task_dict = task.to_dict()
        
        self.assertEqual(task_dict['id'], 1)
        self.assertEqual(task_dict['title'], "Test Task")
        self.assertEqual(task_dict['status'], "pending")
        self.assertEqual(task_dict['priority'], "high")


class TestMessageModel(unittest.TestCase):
    """Test Message model"""
    
    def test_message_to_dict(self):
        """Test message serialization"""
        message = Message()
        message.id = 1
        message.sender_id = 1
        message.receiver_id = 2
        message.subject = "Test Subject"
        message.content = "Test content"
        message.is_read = False
        message.created_at = datetime.now()
        
        message_dict = message.to_dict()
        
        self.assertEqual(message_dict['id'], 1)
        self.assertEqual(message_dict['sender_id'], 1)
        self.assertEqual(message_dict['receiver_id'], 2)
        self.assertEqual(message_dict['subject'], "Test Subject")
        self.assertFalse(message_dict['is_read'])


class TestAdminPasswordConfiguration(unittest.TestCase):
    """Tests to verify that admin credentials are read from environment variables
    and that no hardcoded passwords are present (CWE-798 remediation)."""

    def test_config_admin_password_reads_from_env(self):
        """ADMIN_PASSWORD in Config must come from the ADMIN_PASSWORD env var."""
        with patch.dict(os.environ, {'ADMIN_PASSWORD': 'EnvSuppliedSecret!'}, clear=False):
            # Re-import Config so it picks up the patched environment
            import importlib
            import config as cfg_module
            importlib.reload(cfg_module)
            self.assertEqual(cfg_module.Config.ADMIN_PASSWORD, 'EnvSuppliedSecret!')

    def test_config_admin_password_is_none_when_env_unset(self):
        """Config.ADMIN_PASSWORD must be None (not a hardcoded string) when env var is absent."""
        env_without_admin = {k: v for k, v in os.environ.items() if k != 'ADMIN_PASSWORD'}
        with patch.dict(os.environ, env_without_admin, clear=True):
            import importlib
            import config as cfg_module
            importlib.reload(cfg_module)
            self.assertIsNone(cfg_module.Config.ADMIN_PASSWORD,
                              "ADMIN_PASSWORD must not have a hardcoded fallback")

    def test_config_admin_email_reads_from_env(self):
        """ADMIN_EMAIL in Config must accept an override from the environment."""
        with patch.dict(os.environ, {'ADMIN_EMAIL': 'ops@example.com'}, clear=False):
            import importlib
            import config as cfg_module
            importlib.reload(cfg_module)
            self.assertEqual(cfg_module.Config.ADMIN_EMAIL, 'ops@example.com')

    def test_init_db_raises_when_admin_password_not_set(self):
        """init_db must raise RuntimeError when ADMIN_PASSWORD env var is absent."""
        env_without_admin = {k: v for k, v in os.environ.items() if k != 'ADMIN_PASSWORD'}
        with patch.dict(os.environ, env_without_admin, clear=True):
            import importlib
            import config as cfg_module
            importlib.reload(cfg_module)

            # Build a minimal Flask app context mock
            import database as db_module
            importlib.reload(db_module)

            mock_query = MagicMock()
            mock_query.filter_by.return_value.first.return_value = None

            mock_user_class = MagicMock()
            mock_user_class.query = mock_query

            mock_db = MagicMock()
            mock_db.create_all = MagicMock()

            mock_app = MagicMock()
            mock_app.app_context.return_value.__enter__ = MagicMock(return_value=None)
            mock_app.app_context.return_value.__exit__ = MagicMock(return_value=False)

            with patch.object(db_module, 'User', mock_user_class), \
                 patch.object(db_module, 'db', mock_db), \
                 patch.object(db_module, 'seed_data', MagicMock()):
                with self.assertRaises(RuntimeError) as ctx:
                    db_module.init_db(mock_app)
            self.assertIn('ADMIN_PASSWORD', str(ctx.exception))

    def test_init_db_uses_env_password_not_hardcoded(self):
        """init_db must call set_password with the env-supplied password, not a literal."""
        secret = 'RandomEnvPassword#2024'
        with patch.dict(os.environ, {'ADMIN_PASSWORD': secret}, clear=False):
            import importlib
            import config as cfg_module
            importlib.reload(cfg_module)
            import database as db_module
            importlib.reload(db_module)

            mock_query = MagicMock()
            mock_query.filter_by.return_value.first.return_value = None

            created_user = MagicMock()
            mock_user_class = MagicMock(return_value=created_user)
            mock_user_class.query = mock_query

            mock_db = MagicMock()
            mock_db.create_all = MagicMock()

            mock_app = MagicMock()
            mock_app.app_context.return_value.__enter__ = MagicMock(return_value=None)
            mock_app.app_context.return_value.__exit__ = MagicMock(return_value=False)

            with patch.object(db_module, 'User', mock_user_class), \
                 patch.object(db_module, 'db', mock_db), \
                 patch.object(db_module, 'seed_data', MagicMock()):
                db_module.init_db(mock_app)

            # Verify set_password was called with the env-supplied value
            created_user.set_password.assert_called_once_with(secret)

    def test_no_hardcoded_password_in_database_py(self):
        """database.py must not contain the literal string 'Admin' as a password assignment."""
        db_path = os.path.join(os.path.dirname(__file__), '..', 'database.py')
        with open(os.path.normpath(db_path)) as fh:
            source = fh.read()
        # The old hardcoded line was: admin_password = 'Admin'
        # Verify it no longer exists
        self.assertNotIn("admin_password = 'Admin'", source,
                         "Hardcoded admin_password literal found in database.py")
        self.assertNotIn('admin_password = "Admin"', source,
                         "Hardcoded admin_password literal found in database.py")

    def test_no_hardcoded_api_key_in_database_py(self):
        """database.py must not contain the literal hardcoded admin API key."""
        db_path = os.path.join(os.path.dirname(__file__), '..', 'database.py')
        with open(os.path.normpath(db_path)) as fh:
            source = fh.read()
        self.assertNotIn('admin_api_key_12345', source,
                         "Hardcoded admin API key literal found in database.py")

    def test_no_hardcoded_password_in_config_py(self):
        """config.py must not contain the literal hardcoded ADMIN_PASSWORD value."""
        cfg_path = os.path.join(os.path.dirname(__file__), '..', 'config.py')
        with open(os.path.normpath(cfg_path)) as fh:
            source = fh.read()
        self.assertNotIn('"admin123"', source,
                         "Hardcoded admin123 password found in config.py")
        self.assertNotIn("'admin123'", source,
                         "Hardcoded admin123 password found in config.py")


if __name__ == '__main__':
    unittest.main()

