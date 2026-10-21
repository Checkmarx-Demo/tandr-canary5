"""
Security tests for SQL injection remediation in tasks route.

Tests verify that:
1. The search parameter is handled via parameterized queries (no SQL injection).
2. The project_id filter is also passed as a bound parameter.
3. Normal search functionality continues to work correctly.
4. Malicious payloads do not disrupt or expose unintended data.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Fixtures are inherited from conftest.py (app, client, db_session,
# sample_user, sample_project, sample_task, auth_headers).
# ---------------------------------------------------------------------------


@pytest.fixture
def second_project(db_session, sample_user):
    """A second project whose tasks must NOT appear in results for the first."""
    from models import Project
    project = Project(
        name='Other Project',
        description='Another project',
        owner_id=sample_user.id,
        is_public=False
    )
    db_session.add(project)
    db_session.commit()
    return project


@pytest.fixture
def second_task(db_session, second_project, sample_user):
    """A task belonging to the second project."""
    from models import Task
    task = Task(
        title='Other Task',
        description='Task in a different project',
        project_id=second_project.id,
        created_by=sample_user.id,
        status='pending',
        priority='low'
    )
    db_session.add(task)
    db_session.commit()
    return task


@pytest.fixture
def secret_task(db_session, second_project, sample_user):
    """A task that should never surface when querying with a different project_id."""
    from models import Task
    task = Task(
        title='Secret Confidential Task',
        description='This task must not leak via injection',
        project_id=second_project.id,
        created_by=sample_user.id,
        status='pending',
        priority='high'
    )
    db_session.add(task)
    db_session.commit()
    return task


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get_tasks(client, auth_headers, **params):
    """Convenience wrapper around GET /api/tasks."""
    return client.get('/api/tasks', query_string=params, headers=auth_headers)


# ---------------------------------------------------------------------------
# Positive / functional tests
# ---------------------------------------------------------------------------

class TestGetTasksSearchFunctionality:
    """Normal search functionality must still work after the fix."""

    def test_search_returns_matching_tasks(
        self, client, auth_headers, sample_task, app
    ):
        """A search term matching the task title returns that task."""
        with app.app_context():
            response = _get_tasks(client, auth_headers, search='Test Task')
            assert response.status_code == 200
            data = response.get_json()
            assert 'tasks' in data
            titles = [t['title'] for t in data['tasks']]
            assert 'Test Task' in titles

    def test_search_returns_tasks_matching_description(
        self, client, auth_headers, sample_task, app
    ):
        """A search term matching a task description returns that task."""
        with app.app_context():
            response = _get_tasks(client, auth_headers, search='A test task')
            assert response.status_code == 200
            data = response.get_json()
            assert 'tasks' in data
            assert len(data['tasks']) >= 1

    def test_search_with_project_id_filters_correctly(
        self,
        client,
        auth_headers,
        sample_task,
        second_task,
        sample_project,
        app,
    ):
        """Combining search + project_id must only return tasks in that project."""
        with app.app_context():
            response = _get_tasks(
                client,
                auth_headers,
                search='Task',
                project_id=str(sample_project.id),
            )
            assert response.status_code == 200
            data = response.get_json()
            returned_ids = [t['id'] for t in data['tasks']]
            # sample_task belongs to sample_project and should appear
            assert sample_task.id in returned_ids
            # second_task belongs to a different project and must NOT appear
            assert second_task.id not in returned_ids

    def test_search_no_results_for_nonexistent_term(
        self, client, auth_headers, sample_task, app
    ):
        """A search for a term that matches nothing returns an empty list."""
        with app.app_context():
            response = _get_tasks(
                client, auth_headers, search='xyzzy_no_match_12345'
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['tasks'] == []

    def test_no_search_param_uses_orm_path(
        self, client, auth_headers, sample_task, app
    ):
        """Without a search param the ORM-based code path is used."""
        with app.app_context():
            response = _get_tasks(client, auth_headers)
            assert response.status_code == 200
            data = response.get_json()
            assert 'tasks' in data


# ---------------------------------------------------------------------------
# SQL-injection security tests
# ---------------------------------------------------------------------------

class TestGetTasksSQLInjectionPrevention:
    """
    Verify that SQL injection payloads in 'search' and 'project_id' are
    treated as literal data, not SQL syntax.

    With the old code (`f"...WHERE title LIKE '%{search}%'"`) the payloads
    below would alter the query structure.  With parameterized queries they
    are inert strings and must NOT cause:
      - disclosure of tasks from other projects
      - HTTP 500 errors (database parse errors)
      - extra rows leaking from the database
    """

    def test_injection_in_search_does_not_return_all_rows(
        self,
        client,
        auth_headers,
        sample_project,
        secret_task,
        app,
    ):
        """
        Classic '  OR 1=1 -- ' injection must NOT return every row in the
        tasks table; the LIKE match must be literal.
        """
        payload = "' OR '1'='1"
        with app.app_context():
            response = _get_tasks(
                client,
                auth_headers,
                search=payload,
                project_id=str(sample_project.id),
            )
            # Must not crash
            assert response.status_code == 200
            data = response.get_json()
            # secret_task lives in a DIFFERENT project; injection would have
            # leaked it via 'OR 1=1'.  With parameterized queries it must not.
            returned_ids = [t['id'] for t in data['tasks']]
            assert secret_task.id not in returned_ids

    def test_union_injection_in_search_does_not_leak_data(
        self,
        client,
        auth_headers,
        secret_task,
        app,
    ):
        """
        UNION-based injection payload must not expose extra rows.
        """
        payload = "x' UNION SELECT * FROM tasks --"
        with app.app_context():
            response = _get_tasks(client, auth_headers, search=payload)
            assert response.status_code == 200
            data = response.get_json()
            # No task has a title literally equal to the injection string,
            # so the result must be empty.
            assert data['tasks'] == []

    def test_comment_injection_in_search_does_not_alter_query(
        self,
        client,
        auth_headers,
        secret_task,
        sample_project,
        app,
    ):
        """
        SQL comment injection ('--' / '/**/') must not strip the project_id
        filter, thereby leaking tasks from other projects.
        """
        payload = "Test' --"
        with app.app_context():
            response = _get_tasks(
                client,
                auth_headers,
                search=payload,
                project_id=str(sample_project.id),
            )
            assert response.status_code == 200
            data = response.get_json()
            returned_ids = [t['id'] for t in data['tasks']]
            assert secret_task.id not in returned_ids

    def test_semicolon_injection_in_search_does_not_execute_second_statement(
        self,
        client,
        auth_headers,
        app,
    ):
        """
        Stacked-query injection via ';' must not cause a server error or
        execute a second SQL statement.
        """
        payload = "'; DROP TABLE tasks; --"
        with app.app_context():
            response = _get_tasks(client, auth_headers, search=payload)
            # The endpoint must not crash (500)
            assert response.status_code == 200

    def test_null_byte_in_search_does_not_crash_endpoint(
        self,
        client,
        auth_headers,
        app,
    ):
        """
        A NUL byte (\x00) embedded in the search value must not crash the
        endpoint; it should be treated as a literal character.
        """
        payload = "test\x00injection"
        with app.app_context():
            response = _get_tasks(client, auth_headers, search=payload)
            assert response.status_code == 200

    def test_injection_in_project_id_does_not_bypass_filter(
        self,
        client,
        auth_headers,
        sample_task,
        secret_task,
        app,
    ):
        """
        An injection payload in project_id must not bypass the project filter.
        With parameterized queries the value is bound as a typed parameter so
        the DB will attempt a type-coercion, NOT SQL parsing.
        The endpoint must respond without a 500 error.
        """
        payload = "1 OR 1=1"
        with app.app_context():
            response = _get_tasks(
                client,
                auth_headers,
                search='Task',
                project_id=payload,
            )
            # Either no results (type mismatch treated safely) or a 400/422,
            # but never a 500 caused by raw SQL injection.
            assert response.status_code in (200, 400, 422)
            if response.status_code == 200:
                # If the DB coerced to integer it would fail the bind — either
                # way secret_task must not appear.
                data = response.get_json()
                returned_ids = [t['id'] for t in data['tasks']]
                assert secret_task.id not in returned_ids

    def test_search_with_special_characters_treated_as_literals(
        self,
        client,
        auth_headers,
        app,
    ):
        """
        SQL wildcard characters ('%', '_') passed by the user should be
        treated as literal characters in the LIKE pattern, not as wildcards
        that the user controls at the SQL level.  The endpoint must not crash.
        """
        payload = "% OR %"
        with app.app_context():
            response = _get_tasks(client, auth_headers, search=payload)
            assert response.status_code == 200
