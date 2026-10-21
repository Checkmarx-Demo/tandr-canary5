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
    """
    Tests that verify the global_search endpoint is not vulnerable to SQL injection.
    The fix replaces f-string interpolation with SQLAlchemy parameterized queries
    (text() with a bound :pattern parameter), so user input is never embedded
    directly in the SQL string.
    """

    def test_search_query_uses_parameterized_text(self):
        """
        The raw SQL strings in global_search must NOT contain user-controlled data
        embedded via f-strings or % formatting — they must use a named placeholder.
        """
        import ast
        import inspect
        import textwrap

        route_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "routes", "api.py"
        )
        with open(route_path) as fh:
            source = fh.read()

        tree = ast.parse(source)

        # Collect every string literal that appears as the first argument to
        # db.session.execute(text(...)) calls inside global_search.
        sql_literals = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
            ):
                # The first arg should be text(...)
                if node.args:
                    first = node.args[0]
                    if (
                        isinstance(first, ast.Call)
                        and isinstance(first.func, ast.Name)
                        and first.func.id == "text"
                        and first.args
                        and isinstance(first.args[0], ast.Constant)
                    ):
                        sql_literals.append(first.args[0].value)

        self.assertTrue(
            len(sql_literals) > 0,
            "Expected at least one db.session.execute(text(...)) call in api.py"
        )

        for sql in sql_literals:
            # The literal SQL must not contain Python f-string braces with
            # the variable name (already enforced by ast.Constant matching above —
            # f-strings are JoinedStr nodes, not Constant).
            self.assertIn(
                ":pattern", sql,
                f"SQL literal does not use :pattern placeholder: {sql!r}"
            )
            # Must not contain the bare query variable interpolated in
            self.assertNotIn("{query}", sql)
            self.assertNotIn("%s", sql)

    def test_global_search_sql_strings_are_not_fstrings(self):
        """
        Verify via AST that no JoinedStr (f-string) nodes embed the 'query'
        variable directly into any SQL-like string in global_search.
        """
        import ast

        route_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "routes", "api.py"
        )
        with open(route_path) as fh:
            source = fh.read()

        tree = ast.parse(source)

        # Find the global_search function
        global_search_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "global_search":
                global_search_fn = node
                break

        self.assertIsNotNone(global_search_fn, "global_search function not found in api.py")

        # Walk all nodes inside global_search and look for JoinedStr (f-string)
        # nodes that contain a 'query' name reference — those would be
        # dangerous interpolations into SQL.
        dangerous_fstrings = []
        for node in ast.walk(global_search_fn):
            if isinstance(node, ast.JoinedStr):
                # Check if any FormattedValue inside references 'query'
                for part in ast.walk(node):
                    if isinstance(part, ast.Name) and part.id == "query":
                        dangerous_fstrings.append(node)
                        break

        self.assertEqual(
            len(dangerous_fstrings), 0,
            "Found f-string(s) embedding 'query' variable directly in global_search — "
            "SQL injection risk: use parameterized queries instead."
        )

    def test_like_pattern_is_built_safely(self):
        """
        The LIKE wildcard wrapper ('%' + query + '%') should be constructed
        in Python (as a plain string assignment), not inside the SQL text literal.
        The SQL text literals must contain only :pattern, not LIKE '%...%' with
        embedded data.
        """
        import ast

        route_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "routes", "api.py"
        )
        with open(route_path) as fh:
            source = fh.read()

        tree = ast.parse(source)

        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and node.args
            ):
                first = node.args[0]
                if (
                    isinstance(first, ast.Call)
                    and isinstance(first.func, ast.Name)
                    and first.func.id == "text"
                    and first.args
                    and isinstance(first.args[0], ast.Constant)
                ):
                    sql_text = first.args[0].value
                    # The SQL must NOT contain raw '%query%' interpolation
                    self.assertNotIn(
                        "%" + "{query}" + "%", sql_text,
                        f"SQL literal appears to embed query directly: {sql_text!r}"
                    )

    def test_parameterized_dict_passed_to_execute(self):
        """
        db.session.execute(text(...), params) must receive a dict as the second
        argument, confirming parameterized binding is used.
        """
        import ast

        route_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "routes", "api.py"
        )
        with open(route_path) as fh:
            source = fh.read()

        tree = ast.parse(source)

        execute_calls_with_params = []
        execute_calls_without_params = []

        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and node.args
            ):
                first = node.args[0]
                if (
                    isinstance(first, ast.Call)
                    and isinstance(first.func, ast.Name)
                    and first.func.id == "text"
                ):
                    # Check if a params dict is passed
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Dict):
                        execute_calls_with_params.append(node)
                    elif node.keywords:
                        execute_calls_with_params.append(node)
                    else:
                        execute_calls_without_params.append(node)

        self.assertEqual(
            len(execute_calls_without_params), 0,
            f"Found {len(execute_calls_without_params)} execute(text(...)) call(s) "
            "without a parameters dict — all must pass bound parameters."
        )
        self.assertGreater(
            len(execute_calls_with_params), 0,
            "Expected at least one execute(text(...), params) call with bound parameters."
        )


if __name__ == '__main__':
    unittest.main()

