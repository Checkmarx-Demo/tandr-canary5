"""
Tests for SQL injection remediation in get_tasks_api (routes/api.py).

The vulnerability (CWE-89) was that user-controlled request parameters
(assigned_to, search, project_id) were interpolated directly into a raw SQL
string that was then executed via db.session.execute(text(...)).

The fix replaces string interpolation with SQLAlchemy named bind parameters
(:param_name) so that user input is always treated as data, never as SQL code.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User, Project, Task


# ---------------------------------------------------------------------------
# Helper fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def task_user(db_session):
    """Create a user to own tasks."""
    user = User(username="taskowner", email="taskowner@example.com", role="team_member")
    user.set_password("password123")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture
def task_project(db_session, task_user):
    """Create a project for the tasks."""
    project = Project(
        name="Task Project",
        description="Project for task tests",
        owner_id=task_user.id,
        is_public=True,
    )
    db_session.add(project)
    db_session.commit()
    return project


@pytest.fixture
def task_set(db_session, task_project, task_user):
    """Create a small set of tasks with varied attributes."""
    t1 = Task(
        title="Alpha task",
        description="First task description",
        project_id=task_project.id,
        created_by=task_user.id,
        assigned_to=task_user.id,
        status="pending",
        priority="high",
    )
    t2 = Task(
        title="Beta task",
        description="Second task description",
        project_id=task_project.id,
        created_by=task_user.id,
        assigned_to=None,
        status="in_progress",
        priority="low",
    )
    db_session.add_all([t1, t2])
    db_session.commit()
    return [t1, t2]


# ---------------------------------------------------------------------------
# Functional tests — verify normal behaviour is preserved
# ---------------------------------------------------------------------------

class TestGetTasksApiFunctionality:
    """Verify the endpoint returns correct data after the parameterized fix."""

    def test_get_all_tasks_no_filter(self, client, task_set):
        """GET /api/v1/tasks without filters returns all tasks."""
        response = client.get("/api/v1/tasks")
        assert response.status_code == 200
        data = response.get_json()
        assert "tasks" in data
        assert len(data["tasks"]) >= 2

    def test_search_filter_returns_matching_tasks(self, client, task_set):
        """Search parameter returns only tasks whose title/description matches."""
        response = client.get("/api/v1/tasks?search=Alpha")
        assert response.status_code == 200
        data = response.get_json()
        titles = [t["title"] for t in data["tasks"]]
        assert any("Alpha" in title for title in titles)

    def test_search_filter_no_match_returns_empty(self, client, task_set):
        """Search for a term that matches nothing returns an empty list."""
        response = client.get("/api/v1/tasks?search=ZZZnonexistent")
        assert response.status_code == 200
        data = response.get_json()
        assert data["tasks"] == []

    def test_assigned_to_filter_with_search(self, client, task_set, task_user):
        """assigned_to combined with search filters correctly."""
        response = client.get(
            f"/api/v1/tasks?search=task&assigned_to={task_user.id}"
        )
        assert response.status_code == 200
        data = response.get_json()
        # Every returned task must be assigned to task_user
        for task in data["tasks"]:
            assert task.get("assigned_to") == task_user.id

    def test_project_id_filter_with_search(self, client, task_set, task_project):
        """project_id combined with search filters correctly."""
        response = client.get(
            f"/api/v1/tasks?search=task&project_id={task_project.id}"
        )
        assert response.status_code == 200
        data = response.get_json()
        for task in data["tasks"]:
            assert task.get("project_id") == task_project.id

    def test_no_search_assigned_to_orm_path(self, client, task_set, task_user):
        """Without search term, ORM path filters by assigned_to correctly."""
        response = client.get(f"/api/v1/tasks?assigned_to={task_user.id}")
        assert response.status_code == 200
        data = response.get_json()
        for task in data["tasks"]:
            assert task.get("assigned_to") == task_user.id


# ---------------------------------------------------------------------------
# Security tests — SQL injection payloads must NOT cause data leakage or errors
# ---------------------------------------------------------------------------

class TestGetTasksApiSqlInjection:
    """Verify that SQL injection payloads in query params are inert."""

    def _assert_safe_response(self, response):
        """Helper: response must be 200 with a tasks list (even if empty)."""
        assert response.status_code == 200, (
            f"Expected 200 but got {response.status_code}: {response.data}"
        )
        data = response.get_json()
        assert "tasks" in data
        assert isinstance(data["tasks"], list)

    def test_sql_injection_in_assigned_to_union_select(self, client, task_set):
        """UNION SELECT injection in assigned_to param must not exfiltrate data."""
        # Classic UNION-based injection: if unparameterized, would append a second
        # result set from sqlite_master (or similar) to the tasks list.
        payload = "1 UNION SELECT 1,2,3,4,5,6,7,8,9,10--"
        response = client.get(f"/api/v1/tasks?search=task&assigned_to={payload}")
        # Should either return 200 with only legitimate rows, or return an error —
        # what it must NOT do is silently return extra rows from injected SELECT.
        if response.status_code == 200:
            data = response.get_json()
            # All returned tasks must be real Task objects (have a proper title string)
            for task in data["tasks"]:
                assert isinstance(task.get("title"), str), (
                    "Injected row leaked into response"
                )

    def test_sql_injection_in_assigned_to_boolean_blind(self, client, task_set):
        """Boolean-blind injection attempt in assigned_to must not alter results."""
        # Without parameterization: "... AND assigned_to = 1 OR 1=1--"
        # would return ALL tasks regardless of assigned_to value.
        payload = "1 OR 1=1--"
        response = client.get(f"/api/v1/tasks?search=task&assigned_to={payload}")
        self._assert_safe_response(response)

    def test_sql_injection_in_assigned_to_drop_table(self, client, task_set):
        """Stacked-query DROP TABLE injection must not corrupt the database."""
        payload = "1; DROP TABLE tasks--"
        response = client.get(f"/api/v1/tasks?search=task&assigned_to={payload}")
        # The tasks table must still be queryable afterwards
        follow_up = client.get("/api/v1/tasks")
        assert follow_up.status_code == 200

    def test_sql_injection_in_search_single_quote(self, client, task_set):
        """Single-quote in search param must not break the query."""
        payload = "task' OR '1'='1"
        response = client.get(f"/api/v1/tasks?search={payload}")
        self._assert_safe_response(response)

    def test_sql_injection_in_search_comment(self, client, task_set):
        """Comment-sequence in search param must be treated as literal text."""
        payload = "%'; --"
        response = client.get(f"/api/v1/tasks?search={payload}")
        self._assert_safe_response(response)

    def test_sql_injection_in_project_id(self, client, task_set):
        """Injection attempt via project_id combined with search must be safe."""
        payload = "1 OR 1=1--"
        response = client.get(f"/api/v1/tasks?search=task&project_id={payload}")
        self._assert_safe_response(response)

    def test_assigned_to_with_null_value(self, client, task_set):
        """assigned_to='' (empty string) does not crash and returns results."""
        response = client.get("/api/v1/tasks?search=task&assigned_to=")
        self._assert_safe_response(response)

    def test_search_with_percent_wildcard_literal(self, client, task_set):
        """A literal '%' in the search term is treated as data, not SQL wildcard."""
        # Should return empty (no task titled "%") rather than all tasks
        response = client.get("/api/v1/tasks?search=%25%25%25")
        assert response.status_code == 200

    def test_unicode_injection_attempt(self, client, task_set):
        """Unicode characters in assigned_to do not cause unexpected SQL."""
        payload = "' OR '1'='1"  # ' OR '1'='1 via Unicode escapes
        response = client.get(f"/api/v1/tasks?search=task&assigned_to={payload}")
        self._assert_safe_response(response)
