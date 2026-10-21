"""
Tests for SQL injection remediation in get_tasks_api endpoint.

Verifies that the /api/v1/tasks route uses parameterized queries so that
user-supplied search values cannot alter the SQL command structure.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tasks_with_data(db_session, sample_project, sample_user):
    """Seed two tasks to exercise search results."""
    from models import Task

    task1 = Task(
        title="Fix login bug",
        description="The login page throws a 500 error",
        project_id=sample_project.id,
        created_by=sample_user.id,
        status="pending",
        priority="high",
    )
    task2 = Task(
        title="Write unit tests",
        description="Add coverage for the auth module",
        project_id=sample_project.id,
        created_by=sample_user.id,
        status="in_progress",
        priority="medium",
    )
    db_session.add_all([task1, task2])
    db_session.commit()
    return [task1, task2]


# ---------------------------------------------------------------------------
# Positive functionality tests
# ---------------------------------------------------------------------------

class TestGetTasksApiSearchFunctionality:
    """Verify that legitimate search requests still work after the fix."""

    def test_no_search_returns_all_tasks(self, client, tasks_with_data):
        """Calling /tasks without a search param returns all seeded tasks."""
        response = client.get("/api/v1/tasks")
        assert response.status_code == 200
        data = response.get_json()
        assert "tasks" in data
        assert len(data["tasks"]) >= 2

    def test_search_matches_title(self, client, tasks_with_data):
        """A normal keyword search returns tasks whose title matches."""
        response = client.get("/api/v1/tasks?search=login")
        assert response.status_code == 200
        data = response.get_json()
        titles = [t["title"] for t in data["tasks"]]
        assert any("login" in t.lower() for t in titles)

    def test_search_matches_description(self, client, tasks_with_data):
        """A normal keyword search returns tasks whose description matches."""
        response = client.get("/api/v1/tasks?search=coverage")
        assert response.status_code == 200
        data = response.get_json()
        descriptions = [t.get("description", "") for t in data["tasks"]]
        assert any("coverage" in d.lower() for d in descriptions)

    def test_empty_search_returns_all_tasks(self, client, tasks_with_data):
        """An empty search string returns all tasks (falls through to ORM path)."""
        response = client.get("/api/v1/tasks?search=")
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["tasks"]) >= 2

    def test_search_no_match_returns_empty(self, client, tasks_with_data):
        """A search term that matches nothing returns an empty list."""
        response = client.get("/api/v1/tasks?search=zzznomatch")
        assert response.status_code == 200
        data = response.get_json()
        assert data["tasks"] == []

    def test_search_with_project_id_filter(self, client, tasks_with_data, sample_project):
        """search combined with project_id filter still returns correct tasks."""
        response = client.get(
            f"/api/v1/tasks?search=login&project_id={sample_project.id}"
        )
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data["tasks"], list)


# ---------------------------------------------------------------------------
# SQL injection attack tests
# ---------------------------------------------------------------------------

class TestGetTasksApiSqlInjectionPrevention:
    """Ensure that SQL injection payloads in the search parameter are treated
    as literal string values and do NOT alter query semantics."""

    def test_classic_or_1_equals_1_does_not_return_all_rows(
        self, client, tasks_with_data
    ):
        """The classic `' OR '1'='1` payload must NOT return all rows.

        With string interpolation the injected SQL would be:
            title LIKE '%' OR '1'='1' -- %'
        which always evaluates to TRUE, leaking the full table.
        With parameterized queries the payload is treated as a literal LIKE
        pattern, which matches nothing.
        """
        payload = "' OR '1'='1"
        response = client.get(f"/api/v1/tasks?search={payload}")
        assert response.status_code == 200
        data = response.get_json()
        # The injection payload is not a valid LIKE pattern for any task title/desc
        assert data["tasks"] == [], (
            "SQL injection payload returned rows — parameterization is not working"
        )

    def test_union_select_payload_does_not_expose_data(
        self, client, tasks_with_data
    ):
        """A UNION-based injection payload must be treated as a search term."""
        payload = "x' UNION SELECT 1,2,3,4,5,6,7,8,9,10--"
        response = client.get(f"/api/v1/tasks?search={payload}")
        # The endpoint must not crash and must not return fabricated rows
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data["tasks"], list)
        assert data["tasks"] == []

    def test_drop_table_payload_does_not_execute(self, client, tasks_with_data):
        """A DROP TABLE payload must be ignored and tables must remain intact."""
        payload = "'; DROP TABLE tasks; --"
        response = client.get(f"/api/v1/tasks?search={payload}")
        assert response.status_code == 200

        # Verify the tasks table still exists and contains data
        response2 = client.get("/api/v1/tasks")
        assert response2.status_code == 200
        data2 = response2.get_json()
        assert len(data2["tasks"]) >= 2, (
            "Tasks table appears empty after DROP TABLE payload — injection succeeded"
        )

    def test_tautology_with_comment_does_not_bypass_filter(
        self, client, tasks_with_data
    ):
        """Tautology + comment injection must not bypass the LIKE filter."""
        payload = "x%' OR 1=1 --"
        response = client.get(f"/api/v1/tasks?search={payload}")
        assert response.status_code == 200
        data = response.get_json()
        assert data["tasks"] == []

    def test_null_byte_in_search_does_not_cause_error(self, client, tasks_with_data):
        """A NUL byte (%00) in the query string must not crash the endpoint.

        The NUL byte is expressed as the URL-encoded form (%00) in the query
        string rather than as a literal control byte in the source file.
        """
        # %00 is the URL-encoded NUL byte — passed as a query-string literal
        response = client.get("/api/v1/tasks?search=test\x00injection")
        # Must not 500; results may be empty but the endpoint stays stable
        assert response.status_code in (200, 400)

    def test_percent_wildcard_treated_as_literal(self, client, tasks_with_data):
        """A bare % in the search term must be treated as a literal character,
        not as a SQL wildcard that could match every row.

        Note: In SQLite LIKE, % is a wildcard at the SQL level, but the
        parameterized query surrounds the value with explicit % wildcards,
        so a user-supplied % becomes %user_%% which still behaves as a
        bounded search and does NOT return all rows unless they happen to
        contain a % character in their title/description.
        """
        # Our seeded tasks don't contain '%' characters, so this should be empty
        response = client.get("/api/v1/tasks?search=%25")
        assert response.status_code == 200
        data = response.get_json()
        # No rows contain a literal '%' in their title/description
        assert data["tasks"] == []


# ---------------------------------------------------------------------------
# Regression: verify the raw SQL no longer contains user input verbatim
# ---------------------------------------------------------------------------

class TestGetTasksApiQueryParameterization:
    """White-box tests: inspect the SQLAlchemy text() call to ensure bind
    parameters are used instead of string interpolation."""

    def test_routes_api_uses_bind_parameter_not_format(self):
        """The source of get_tasks_api must use ':search' bind parameter syntax,
        not .format() or f-string interpolation to embed the search value."""
        routes_api_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "routes",
            "api.py",
        )
        with open(routes_api_path, "r") as fh:
            source = fh.read()

        # The parameterized placeholder must be present
        assert ":search" in source, (
            "Bind parameter ':search' not found — query may still be vulnerable"
        )

        # The vulnerable interpolation patterns must be absent from the
        # get_tasks_api function body.  We locate that function's block and
        # check only within it to avoid false positives from other functions.
        func_start = source.find("def get_tasks_api(")
        assert func_start != -1, "get_tasks_api function not found in api.py"

        # Find the next top-level function definition after get_tasks_api
        next_func = source.find("\ndef ", func_start + 1)
        func_body = source[func_start:next_func] if next_func != -1 else source[func_start:]

        assert '"%{}%"'.format("") not in func_body and \
               "LIKE '%{}%'".format("") not in func_body, (
            "Old format-string LIKE interpolation pattern still present in get_tasks_api"
        )
        assert ".format(search" not in func_body, (
            ".format(search, ...) interpolation still present in get_tasks_api"
        )
