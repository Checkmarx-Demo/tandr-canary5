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


class TestGetProjectsApiSQLInjection(unittest.TestCase):
    """
    Tests verifying that the get_projects_api endpoint uses parameterized
    queries and is not vulnerable to SQL injection (CWE-89).
    """

    def _get_api_source(self):
        """Return the source text of the api.py route module."""
        api_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'routes', 'api.py'
        )
        with open(api_path, 'r') as fh:
            return fh.read()

    def test_no_fstring_interpolation_in_sql_query(self):
        """
        The raw SQL query must NOT embed the search term via f-string interpolation.
        Embedding user input directly in a query string enables SQL injection.
        """
        source = self._get_api_source()
        # The dangerous pattern: f-string with {search} inside SQL string
        self.assertNotIn(
            "f\"SELECT",
            source,
            "SQL query must not be built with an f-string (string interpolation)."
        )
        self.assertNotIn(
            "f'SELECT",
            source,
            "SQL query must not be built with an f-string (string interpolation)."
        )

    def test_no_percent_format_interpolation_in_sql_query(self):
        """
        The raw SQL query must NOT embed the search term via %-format or .format().
        """
        source = self._get_api_source()
        # Reject patterns like "... LIKE '%s'" % search or "...".format(search=search)
        self.assertNotRegex(
            source,
            r'SELECT.*%\s*search',
            "SQL query must not use % formatting with user-supplied values."
        )

    def test_parameterized_query_binding_used(self):
        """
        The SQL query must use a named bound parameter (:search) so that the
        database driver handles escaping – not Python string manipulation.
        """
        source = self._get_api_source()
        self.assertIn(
            ":search",
            source,
            "SQL query must use a named bound parameter ':search' instead of "
            "embedding the value directly."
        )

    def test_bound_parameter_dict_passed_to_execute(self):
        """
        db.session.execute() must receive a parameter dictionary containing
        the 'search' key so the bound parameter is actually substituted safely.
        """
        source = self._get_api_source()
        self.assertIn(
            '"search"',
            source,
            "execute() call must pass {'search': ...} as the parameter dict."
        )

    def test_search_wildcard_added_in_python_not_in_sql(self):
        """
        The '%' wildcard characters for LIKE must be appended in Python and
        passed as a bound parameter value, NOT concatenated inside the SQL
        string itself.  This confirms the fix structure is correct.
        """
        source = self._get_api_source()
        # The Python-side wildcard construction must be present
        self.assertIn(
            'search_param',
            source,
            "The LIKE wildcard should be added to a Python variable (search_param) "
            "and passed as a bound parameter, not embedded in the SQL string."
        )
        # The SQL literal must NOT contain a bare % around search interpolation
        self.assertNotIn(
            f"'%{{search}}%'",
            source,
            "The SQL string must not contain f-string braces wrapping search."
        )

    def test_sql_injection_payload_not_in_query_string(self):
        """
        Verify that if a caller somehow tried to inject SQL via the search
        parameter, the code path that builds the query does NOT place that
        value literally inside the query string.  This is a static-analysis
        proxy test: we inspect that the query template is a constant string
        with no runtime concatenation of the search variable.
        """
        source = self._get_api_source()
        # The query template assigned to 'query' must be a plain string using text()
        # and must NOT reference the 'search' variable inside it via concatenation.
        self.assertNotRegex(
            source,
            r'query\s*=\s*[^\n]*\+[^\n]*search',
            "The query string must not be built by concatenating the 'search' variable."
        )

    def test_text_helper_used_for_raw_sql(self):
        """
        SQLAlchemy's text() helper must be used when executing raw SQL so that
        bound parameters are handled correctly by the engine.
        """
        source = self._get_api_source()
        self.assertIn(
            'text(',
            source,
            "SQLAlchemy text() must be used to wrap raw SQL strings."
        )


if __name__ == '__main__':
    unittest.main()

