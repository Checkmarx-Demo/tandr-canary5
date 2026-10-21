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


class TestGlobalSearchSQLInjection(unittest.TestCase):
    """Tests verifying that global_search uses parameterized queries (no SQL injection)."""

    def _get_parameterized_queries(self):
        """Extract the SQL query strings and parameter dicts from the global_search function."""
        import ast
        import inspect
        import re

        route_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'routes', 'api.py'
        )
        with open(route_file, 'r') as fh:
            source = fh.read()
        return source

    def test_no_fstring_sql_in_global_search(self):
        """global_search must NOT embed the query variable directly in the SQL string."""
        source = self._get_parameterized_queries()

        # Detect the classic injection patterns: f-strings with {query} inside SQL LIKE clauses
        bad_patterns = [
            r"f['\"].*LIKE.*\{query\}",
            r"f['\"].*\{query\}.*LIKE",
            r"% \+ query \+",
            r"\"{}\".format\(query\)",
            r"'{}'\s*\.format\(query\)",
        ]
        for pattern in bad_patterns:
            self.assertIsNone(
                re.search(pattern, source),
                msg=f"Unsafe SQL construction pattern detected: {pattern!r}"
            )

    def test_parameterized_bind_variable_present(self):
        """global_search SQL strings must use a named bind parameter (:search)."""
        source = self._get_parameterized_queries()

        # The fix uses :search as the bind variable
        self.assertIn(
            ':search',
            source,
            "Expected named bind parameter ':search' not found in api.py"
        )

    def test_search_param_built_from_query(self):
        """global_search must build the LIKE wildcard string separately from the SQL."""
        source = self._get_parameterized_queries()

        # The safe pattern wraps wildcards in Python, not in SQL
        import re
        self.assertRegex(
            source,
            r'search_param\s*=\s*f["\']%\{query\}%["\']',
            "Expected 'search_param = f\"%{query}%\"' to build the LIKE value in Python"
        )

    def test_sql_text_called_with_literal_string(self):
        """The text() calls in global_search must receive a literal string, not an f-string."""
        source = self._get_parameterized_queries()
        import re

        # Find every text(...) call
        text_calls = re.findall(r'text\(([^)]+)\)', source)
        for call_arg in text_calls:
            # If the argument to text() starts with 'f"' or "f'" it is an f-string — unsafe
            stripped = call_arg.strip()
            self.assertFalse(
                stripped.startswith('f"') or stripped.startswith("f'"),
                msg=f"text() is called with an f-string argument: text({call_arg})"
            )

    def test_sql_injection_payload_not_interpolated(self):
        """
        Ensure the dangerous injection payload characters are never embedded literally
        in the SQL statement strings used in global_search.
        """
        import re

        source = self._get_parameterized_queries()

        # Extract lines that are inside SQL text() calls (lines containing SELECT)
        sql_lines = [line for line in source.splitlines() if 'SELECT' in line and 'text(' in line]

        # None of these lines should contain Python f-string interpolation
        for line in sql_lines:
            self.assertNotIn(
                '{query}', line,
                msg=f"SQL line still interpolates {{query}}: {line.strip()!r}"
            )
            self.assertNotIn(
                '{search_param}', line,
                msg=f"SQL line interpolates {{search_param}} instead of using bind var: {line.strip()!r}"
            )


if __name__ == '__main__':
    unittest.main()

