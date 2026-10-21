"""
Tests for SQL injection vulnerability fix in /backend/routes/projects.py

Verifies that the get_projects endpoint uses parameterized queries and is not
susceptible to SQL injection via the 'search' query parameter (CWE-89).
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestGetProjectsSQLInjection:
    """Tests verifying the SQL injection fix in get_projects."""

    def test_search_returns_matching_projects(self, client, auth_headers, sample_project):
        """Normal search returns matching projects without error."""
        response = client.get(
            '/api/projects?search=Test',
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.get_json()
        assert 'projects' in data

    def test_search_with_empty_string_uses_orm_path(self, client, auth_headers, sample_project):
        """Empty search (no parameter) uses the ORM path and returns all projects."""
        response = client.get('/api/projects', headers=auth_headers)
        assert response.status_code == 200
        data = response.get_json()
        assert 'projects' in data

    def test_sql_injection_single_quote_does_not_cause_error(
        self, client, auth_headers, sample_project
    ):
        """A single-quote payload must not cause a database error (500).

        Without parameterization, `' OR '1'='1` would break the query syntax
        and typically result in an unhandled exception (HTTP 500).  With a
        parameterized query the value is treated as literal data and the
        request succeeds with a 200 response containing no unexpected results.
        """
        payload = "' OR '1'='1"
        response = client.get(
            f'/api/projects?search={payload}',
            headers=auth_headers
        )
        # The server must NOT crash; a 500 would indicate the injection worked.
        assert response.status_code == 200

    def test_sql_injection_union_select_does_not_leak_data(
        self, client, auth_headers, sample_project
    ):
        """A UNION SELECT injection payload must not return extra rows.

        With a vulnerable raw query the UNION could append rows from other
        tables. With parameterized queries the payload is treated as a literal
        LIKE pattern value, which will not match any project name.
        """
        payload = "' UNION SELECT id, username, email, password_hash, role, created_at, updated_at, is_public FROM users--"
        response = client.get(
            f'/api/projects?search={payload}',
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.get_json()
        # The injection must not return rows that look like user records.
        for project in data.get('projects', []):
            # A leaked user row would have 'username' or 'email' keys but NOT 'owner_id'.
            assert 'username' not in project
            assert 'email' not in project

    def test_sql_injection_drop_table_payload_does_not_cause_error(
        self, client, auth_headers, sample_project
    ):
        """A stacked-query DROP TABLE payload must not crash the server."""
        payload = "'; DROP TABLE projects;--"
        response = client.get(
            f'/api/projects?search={payload}',
            headers=auth_headers
        )
        # Must not result in 500; the payload is treated as literal data.
        assert response.status_code == 200

    def test_sql_injection_or_1_equals_1_does_not_return_all_rows(
        self, client, auth_headers, sample_project, db_session
    ):
        """An OR-based tautology must not bypass the WHERE filter.

        If the injection worked, `' OR '1'='1` would make the WHERE clause
        always true, returning every row in the table regardless of the search
        term. With parameterized queries it is treated as a literal LIKE
        pattern, so only projects whose name/description literally contain
        that string are returned (which in this dataset is none).
        """
        from models import Project, User

        # Add a second project that should NOT match the injected "always true" condition
        # when using parameterized queries.
        second_user = User(username='other', email='other@example.com', role='team_member')
        second_user.set_password('pass')
        db_session.add(second_user)
        db_session.flush()

        second_project = Project(
            name='Secret Project',
            description='Should not appear via injection',
            owner_id=second_user.id,
            is_public=False
        )
        db_session.add(second_project)
        db_session.commit()

        # This payload would be `' OR '1'='1` – a tautology in raw SQL.
        payload = "' OR '1'='1"
        response = client.get(
            f'/api/projects?search={payload}',
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.get_json()
        projects = data.get('projects', [])
        # With parameterized queries the literal string won't match any project name,
        # so none (or at most 0) results should be returned rather than every project.
        project_names = [p.get('name') for p in projects]
        assert 'Secret Project' not in project_names

    def test_search_with_sql_wildcard_characters_is_safe(
        self, client, auth_headers, sample_project
    ):
        """SQL wildcard characters in search are treated as literals by the DB driver."""
        # These characters are valid query strings and should not cause a 500.
        for payload in ['%', '_', '%%', "_%_"]:
            response = client.get(
                f'/api/projects?search={payload}',
                headers=auth_headers
            )
            assert response.status_code == 200, (
                f"Payload {payload!r} caused an unexpected status {response.status_code}"
            )

    def test_search_legitimate_term_returns_correct_project(
        self, client, auth_headers, sample_project
    ):
        """A normal search term returns the correct project by name."""
        response = client.get(
            '/api/projects?search=Test Project',
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.get_json()
        # The sample_project fixture creates a project named 'Test Project'.
        # With the parameterized LIKE query it should be found.
        project_names = [p.get('name') for p in data.get('projects', [])]
        assert 'Test Project' in project_names

    def test_search_nonexistent_term_returns_empty_list(
        self, client, auth_headers, sample_project
    ):
        """A search term that matches nothing returns an empty projects list."""
        response = client.get(
            '/api/projects?search=xyzzy_no_match_8675309',
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data.get('projects') == []

    def test_unauthenticated_request_is_rejected(self, client):
        """Requests without auth headers must be rejected (401/403)."""
        response = client.get('/api/projects?search=test')
        assert response.status_code in (401, 403)
