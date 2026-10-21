"""
Tests for SQL injection remediation in the /api/v1/users endpoint.

Verifies that:
1. Normal search functionality works correctly with the parameterized query.
2. SQL injection payloads do not manipulate the query logic.
3. Edge-case inputs are handled safely.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _create_user(db_session, username, email, password="password123"):
    user = User(username=username, email=email, role="team_member")
    user.set_password(password)
    db_session.add(user)
    db_session.commit()
    return user


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGetUsersParameterizedQuery:
    """Tests ensuring the /api/v1/users search is SQL-injection-safe."""

    def test_search_returns_matching_user_by_username(self, client, db_session):
        """A normal search term returns the expected user."""
        _create_user(db_session, "alice", "alice@example.com")
        _create_user(db_session, "bob", "bob@example.com")

        response = client.get("/api/v1/users?search=alice")
        assert response.status_code == 200
        data = response.get_json()
        usernames = [u["username"] for u in data["users"]]
        assert "alice" in usernames
        assert "bob" not in usernames

    def test_search_returns_matching_user_by_email(self, client, db_session):
        """A search term matching the email column returns the correct user."""
        _create_user(db_session, "carol", "carol@example.com")
        _create_user(db_session, "dave", "dave@other.com")

        response = client.get("/api/v1/users?search=carol%40example")
        assert response.status_code == 200
        data = response.get_json()
        usernames = [u["username"] for u in data["users"]]
        assert "carol" in usernames
        assert "dave" not in usernames

    def test_no_search_returns_all_users(self, client, db_session):
        """Omitting the search param returns all users via the ORM path."""
        _create_user(db_session, "eve", "eve@example.com")
        _create_user(db_session, "frank", "frank@example.com")

        response = client.get("/api/v1/users")
        assert response.status_code == 200
        data = response.get_json()
        usernames = [u["username"] for u in data["users"]]
        assert "eve" in usernames
        assert "frank" in usernames

    def test_sql_injection_tautology_does_not_return_all_rows(self, client, db_session):
        """
        Classic tautology payload '%' OR '1'='1 must NOT return rows that do
        not match the literal search string.
        The parameterized query treats the payload as a plain LIKE pattern,
        so only rows whose username/email literally contain the payload
        characters are returned – not all rows.
        """
        _create_user(db_session, "victim", "victim@example.com")
        _create_user(db_session, "other", "other@example.com")

        # This payload would cause all rows to be returned if the query were
        # still built via string concatenation.
        payload = "' OR '1'='1"
        response = client.get(f"/api/v1/users?search={payload}")
        assert response.status_code == 200
        data = response.get_json()
        # With parameterized queries, the payload is treated as a literal
        # LIKE pattern; no user has that exact string in username/email,
        # so the result must be empty.
        assert data["count"] == 0

    def test_sql_injection_union_select_does_not_leak_data(self, client, db_session):
        """
        A UNION-based injection payload must not leak additional rows.
        """
        _create_user(db_session, "target", "target@example.com")

        payload = "' UNION SELECT username, password, email, id, role FROM users--"
        response = client.get(f"/api/v1/users?search={payload}")
        assert response.status_code == 200
        data = response.get_json()
        # The injected UNION clause is treated as literal text by the
        # parameterized query, so only rows whose username/email contain
        # that text verbatim would appear – which is zero rows here.
        assert data["count"] == 0

    def test_sql_injection_comment_does_not_truncate_query(self, client, db_session):
        """
        A comment-based payload (--) must not cause the WHERE clause to be
        truncated or bypassed.
        """
        _create_user(db_session, "safe_user", "safe@example.com")

        payload = "safe'--"
        response = client.get(f"/api/v1/users?search={payload}")
        assert response.status_code == 200
        data = response.get_json()
        # The comment delimiter is passed as literal data; "safe'--" does
        # not match the username "safe_user", so no rows are returned.
        assert data["count"] == 0

    def test_search_with_special_characters_does_not_crash(self, client, db_session):
        """
        Inputs containing SQL metacharacters must be handled without raising
        an exception (the database engine treats them as data, not syntax).
        """
        _create_user(db_session, "normaluser", "normal@example.com")

        for payload in ["%", "_", "\\", "'", '"', ";"]:
            response = client.get(f"/api/v1/users?search={payload}")
            assert response.status_code == 200, (
                f"Expected 200 but got {response.status_code} for payload: {payload!r}"
            )

    def test_response_includes_count_field(self, client, db_session):
        """The response always includes the 'count' field regardless of search."""
        response = client.get("/api/v1/users?search=nobody")
        assert response.status_code == 200
        data = response.get_json()
        assert "count" in data
        assert data["count"] == 0

    def test_empty_search_param_returns_all_users(self, client, db_session):
        """An explicitly empty search parameter falls through to the ORM path."""
        _create_user(db_session, "grace", "grace@example.com")

        response = client.get("/api/v1/users?search=")
        assert response.status_code == 200
        data = response.get_json()
        usernames = [u["username"] for u in data["users"]]
        assert "grace" in usernames
