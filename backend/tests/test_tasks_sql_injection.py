"""
Tests for SQL injection remediation in the tasks route.

The get_tasks endpoint previously built a raw SQL string by interpolating
the `search` query-parameter directly, enabling SQL injection.  The fix
replaces that string interpolation with a SQLAlchemy parameterized query
(text() + named bind parameters), so user-supplied values are always
treated as data, never as SQL syntax.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _auth_headers(app, user):
    """Return Bearer-token headers for the given user."""
    with app.app_context():
        from auth import generate_token
        token = generate_token(user.id, user.username)
        return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Fixtures – reuse conftest fixtures; add a second task for search variety
# ---------------------------------------------------------------------------

@pytest.fixture
def second_task(db_session, sample_project, sample_user):
    """A second task whose title does NOT contain the default search term."""
    from models import Task
    task = Task(
        title="Unrelated Work Item",
        description="Nothing about bugs or security",
        project_id=sample_project.id,
        created_by=sample_user.id,
        status="pending",
        priority="low",
    )
    db_session.add(task)
    db_session.commit()
    return task


# ---------------------------------------------------------------------------
# Positive / functional tests
# ---------------------------------------------------------------------------

class TestGetTasksSearch:
    """Functional tests: search returns correct results."""

    def test_search_returns_matching_task(self, client, app, sample_task, sample_user):
        """A valid search term returns the task whose title matches."""
        headers = _auth_headers(app, sample_user)
        resp = client.get("/api/tasks?search=Test", headers=headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "tasks" in data
        titles = [t["title"] for t in data["tasks"]]
        assert any("Test" in title for title in titles)

    def test_search_no_match_returns_empty(self, client, app, sample_task, sample_user):
        """A search term that matches nothing returns an empty list."""
        headers = _auth_headers(app, sample_user)
        resp = client.get("/api/tasks?search=xyznonexistent999", headers=headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["tasks"] == []

    def test_search_with_project_id_filter(
        self, client, app, sample_task, sample_project, sample_user
    ):
        """Search combined with project_id filter narrows results correctly."""
        headers = _auth_headers(app, sample_user)
        url = f"/api/tasks?search=Test&project_id={sample_project.id}"
        resp = client.get(url, headers=headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "tasks" in data
        # Every returned task must belong to the specified project
        for task in data["tasks"]:
            assert task["project_id"] == sample_project.id

    def test_no_search_returns_all_tasks(
        self, client, app, sample_task, second_task, sample_user
    ):
        """Without a search param the ORM path returns all tasks."""
        headers = _auth_headers(app, sample_user)
        resp = client.get("/api/tasks", headers=headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["tasks"]) >= 2

    def test_search_percent_literal_does_not_explode(
        self, client, app, sample_task, sample_user
    ):
        """A literal '%' character in the search term must not cause an error."""
        headers = _auth_headers(app, sample_user)
        resp = client.get("/api/tasks?search=%25", headers=headers)
        assert resp.status_code == 200

    def test_search_underscore_literal(self, client, app, sample_task, sample_user):
        """A literal '_' character (SQL wildcard) must not cause an error."""
        headers = _auth_headers(app, sample_user)
        resp = client.get("/api/tasks?search=_", headers=headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# SQL injection security tests
# ---------------------------------------------------------------------------

class TestGetTasksSQLInjectionPrevention:
    """
    Security regression tests: SQL injection payloads must NOT cause
    unexpected data disclosure, database errors, or crashes.

    With a parameterized query the payload is treated as a literal string
    value; if it doesn't match any title/description it simply returns [].
    """

    def _inject(self, client, app, user, payload):
        """Helper: GET /api/tasks?search=<payload> and return (status, json)."""
        headers = _auth_headers(app, user)
        resp = client.get(f"/api/tasks?search={payload}", headers=headers)
        return resp.status_code, resp.get_json()

    def test_classic_or_1_equals_1_injection(
        self, client, app, sample_task, sample_user
    ):
        """
        Classic `' OR '1'='1` payload must NOT return all rows.
        A parameterized query treats it as a literal string – no match → [].
        """
        status, data = self._inject(
            client, app, sample_user, "' OR '1'='1"
        )
        assert status == 200
        # The injection payload itself does not appear as a task title,
        # so the parameterized query correctly returns no rows.
        assert data["tasks"] == []

    def test_comment_based_injection(self, client, app, sample_task, sample_user):
        """
        `' OR 1=1 --` payload must not bypass the WHERE clause.
        """
        status, data = self._inject(
            client, app, sample_user, "' OR 1=1 --"
        )
        assert status == 200
        assert data["tasks"] == []

    def test_union_select_injection(self, client, app, sample_task, sample_user):
        """
        UNION-based injection payload must not disclose extra data and
        must not return a 500 server error.
        """
        payload = "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --"
        status, data = self._inject(client, app, sample_user, payload)
        # Must not crash the server
        assert status == 200
        # Parameterized query: payload is just a search string → no match
        assert data["tasks"] == []

    def test_stacked_query_injection(self, client, app, sample_task, sample_user):
        """
        Stacked query payload (`;DROP TABLE tasks;--`) must not cause a 500
        error and must not drop the table (subsequent request still works).
        """
        status, _ = self._inject(
            client, app, sample_user, "'; DROP TABLE tasks; --"
        )
        assert status == 200
        # Table must still exist: subsequent list request succeeds
        headers = _auth_headers(app, sample_user)
        followup = client.get("/api/tasks", headers=headers)
        assert followup.status_code == 200

    def test_null_byte_injection(self, client, app, sample_task, sample_user):
        """
        A NUL byte in the search value (%00) must not crash the application.
        The escape sequence \\x00 represents U+0000 in Python source.
        """
        # Send the null byte URL-encoded so the test client handles it cleanly.
        headers = _auth_headers(app, sample_user)
        resp = client.get("/api/tasks?search=%00evil", headers=headers)
        # Application must not return 500
        assert resp.status_code == 200

    def test_single_quote_in_search_does_not_cause_500(
        self, client, app, sample_task, sample_user
    ):
        """
        A lone single-quote was the primary crash vector before the fix.
        With parameterized queries it is treated as a literal character.
        """
        status, data = self._inject(client, app, sample_user, "'")
        assert status == 200
        assert data["tasks"] == []

    def test_project_id_injection_via_search_path(
        self, client, app, sample_task, sample_project, sample_user
    ):
        """
        Even when project_id is also supplied the search path must use
        parameterized queries for both values.
        """
        headers = _auth_headers(app, sample_user)
        payload = "' OR '1'='1"
        url = f"/api/tasks?search={payload}&project_id={sample_project.id}"
        resp = client.get(url, headers=headers)
        assert resp.status_code == 200
        data = resp.get_json()
        # Injection payload is not a matching title → empty list
        assert data["tasks"] == []
