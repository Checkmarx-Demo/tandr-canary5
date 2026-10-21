"""
Security regression tests for the global_search SQL injection fix.

The global_search endpoint (/api/v1/search?q=...) previously built its SQL
queries via f-string interpolation, allowing attackers to inject arbitrary SQL.
The fix replaces every f-string with a parameterized SQLAlchemy text() call
so the database driver handles escaping and untrusted input never becomes SQL
syntax.

These tests verify:
  1. Normal searches still return correct results.
  2. Classic SQL-injection payloads do NOT exfiltrate extra rows.
  3. Missing / empty query returns 400.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Fixtures reuse conftest.py: app, client, db_session, sample_user,
# sample_project, sample_task.
# ---------------------------------------------------------------------------


class TestGlobalSearchFunctionality:
    """Verify that the search endpoint returns correct results for valid queries."""

    def test_missing_query_returns_400(self, client):
        """Calling /search without ?q= must return 400."""
        response = client.get('/api/v1/search')
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_empty_query_returns_400(self, client):
        """Calling /search with an empty ?q= must return 400."""
        response = client.get('/api/v1/search?q=')
        assert response.status_code == 400

    def test_normal_search_returns_200(self, client, sample_user):
        """A well-formed query must return 200 with the expected result shape."""
        response = client.get('/api/v1/search?q=testuser')
        assert response.status_code == 200
        data = response.get_json()
        assert 'users' in data
        assert 'projects' in data
        assert 'tasks' in data
        assert 'query' in data
        assert data['query'] == 'testuser'

    def test_user_found_by_username(self, client, sample_user):
        """A search for an existing username must return that user."""
        response = client.get('/api/v1/search?q=testuser')
        assert response.status_code == 200
        data = response.get_json()
        usernames = [u.get('username') for u in data['users']]
        assert 'testuser' in usernames

    def test_user_found_by_email(self, client, sample_user):
        """A search matching an e-mail address must return that user."""
        response = client.get('/api/v1/search?q=test@example')
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['users']) >= 1

    def test_project_found_by_name(self, client, sample_project):
        """A search matching a project name must return that project."""
        response = client.get('/api/v1/search?q=Test+Project')
        assert response.status_code == 200
        data = response.get_json()
        names = [p.get('name') for p in data['projects']]
        assert 'Test Project' in names

    def test_task_found_by_title(self, client, sample_task):
        """A search matching a task title must return that task."""
        response = client.get('/api/v1/search?q=Test+Task')
        assert response.status_code == 200
        data = response.get_json()
        titles = [t.get('title') for t in data['tasks']]
        assert 'Test Task' in titles

    def test_no_results_for_nonexistent_term(self, client, sample_user):
        """A query that matches nothing must return empty lists, not an error."""
        response = client.get('/api/v1/search?q=xyzzy_no_match_9999')
        assert response.status_code == 200
        data = response.get_json()
        assert data['users'] == []
        assert data['projects'] == []
        assert data['tasks'] == []


class TestGlobalSearchSQLInjection:
    """
    Verify that SQL injection payloads are treated as literal search terms
    and do NOT cause errors or return unintended extra rows.

    With the original f-string interpolation a payload such as
        ' OR '1'='1
    would produce WHERE … LIKE '%' OR '1'='1'%' which returns every row.
    With the parameterized fix the payload is bound as a data value so the
    LIKE pattern literally becomes:  %' OR '1'='1%  — matching nothing
    or only rows whose text literally contains that string.
    """

    def test_classic_or_injection_users(self, client, sample_user, db_session):
        """
        ' OR '1'='1 must NOT return all users; it is treated as a literal string.
        We seed one user.  If injection worked the query returns ≥1 row regardless.
        We verify the result count does not exceed the number of rows that
        actually contain that literal string (i.e. zero for our seed data).
        """
        from models import User
        total_users = db_session.query(User).count()

        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200
        data = response.get_json()
        # A successful injection would return all users; parameterization returns 0.
        assert len(data['users']) < total_users

    def test_union_select_injection_users(self, client, sample_user):
        """
        A UNION SELECT payload must not produce extra rows or cause a 500 error.
        """
        payload = "' UNION SELECT 1,2,3,4,5,6,7,8--"
        response = client.get(f'/api/v1/search?q={payload}')
        # Must not crash the server.
        assert response.status_code == 200
        data = response.get_json()
        # No rows containing that literal string should exist.
        assert data['users'] == []

    def test_comment_terminator_injection_users(self, client, sample_user, db_session):
        """
        A payload ending in -- (SQL line comment) must not bypass the LIKE filter.
        """
        from models import User
        total_users = db_session.query(User).count()

        payload = "admin'--"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['users']) < total_users

    def test_or_injection_projects(self, client, sample_project, db_session):
        """' OR '1'='1 must NOT return all projects."""
        from models import Project
        total_projects = db_session.query(Project).count()

        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['projects']) < total_projects

    def test_or_injection_tasks(self, client, sample_task, db_session):
        """' OR '1'='1 must NOT return all tasks."""
        from models import Task
        total_tasks = db_session.query(Task).count()

        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200
        data = response.get_json()
        assert len(data['tasks']) < total_tasks

    def test_stacked_query_injection(self, client, sample_user):
        """
        A stacked-query payload (semicolon + DROP TABLE) must not crash the
        endpoint or affect the database (SQLite does not execute stacked
        statements via execute(), but we confirm no 500 is returned).
        """
        payload = "test'; DROP TABLE users;--"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200

    def test_wildcard_percent_treated_as_literal(self, client, sample_user, db_session):
        """
        A bare % must be treated as a literal LIKE wildcard character, not
        as an injection vector.  The endpoint should return 200 without error.
        """
        response = client.get('/api/v1/search?q=%25')  # URL-encoded %
        assert response.status_code == 200

    def test_null_byte_injection(self, client, sample_user):
        """
        A NUL byte embedded in the query (%00 URL-encoded) must not cause a
        500 error or unexpected behavior.
        """
        # Use URL percent-encoding for the NUL byte (\x00) — never a literal
        # control byte in source code.
        response = client.get('/api/v1/search?q=test%00evil')
        # Acceptable outcomes: 200 (treated as literal) or 400 (rejected).
        assert response.status_code in (200, 400)
