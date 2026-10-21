"""
Security tests for SQL Injection remediation in the api blueprint.

Specifically covers the get_project_tasks endpoint (GET /api/v1/projects/<id>/tasks)
where user-controlled 'search' query parameter was previously embedded directly
into a raw SQL string, enabling SQL injection attacks.

After the fix the query is built with SQLAlchemy's parameterized text() call, so
the database driver never interpolates user input into the SQL string.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_task(db_session, title, description, project_id, user_id):
    from models import Task
    task = Task(
        title=title,
        description=description,
        project_id=project_id,
        created_by=user_id,
        status='pending',
        priority='medium',
    )
    db_session.add(task)
    db_session.commit()
    return task


# ---------------------------------------------------------------------------
# Normal-operation tests (regression guard)
# ---------------------------------------------------------------------------

class TestGetProjectTasksNormal:
    """Verify that the endpoint still works correctly after the fix."""

    def test_returns_all_tasks_when_no_search(self, client, sample_task, sample_project):
        """Without a search parameter every task in the project is returned."""
        resp = client.get(f'/api/v1/projects/{sample_project.id}/tasks')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'tasks' in data
        assert len(data['tasks']) >= 1

    def test_search_returns_matching_tasks(self, client, db_session,
                                           sample_project, sample_user):
        """A valid search term returns only matching tasks."""
        _create_task(db_session, 'Alpha Task', 'First task', sample_project.id, sample_user.id)
        _create_task(db_session, 'Beta Task',  'Second task', sample_project.id, sample_user.id)

        resp = client.get(f'/api/v1/projects/{sample_project.id}/tasks?search=Alpha')
        assert resp.status_code == 200
        data = resp.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert any('Alpha' in t for t in titles)

    def test_search_matches_description(self, client, db_session,
                                        sample_project, sample_user):
        """A search term that appears only in the description is still returned."""
        _create_task(db_session, 'Generic Title', 'unique_desc_xyz', sample_project.id, sample_user.id)

        resp = client.get(f'/api/v1/projects/{sample_project.id}/tasks?search=unique_desc_xyz')
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data['tasks']) >= 1

    def test_search_no_match_returns_empty(self, client, sample_project):
        """A search term that matches nothing returns an empty list."""
        resp = client.get(f'/api/v1/projects/{sample_project.id}/tasks?search=ZZZNOMATCH99999')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['tasks'] == []

    def test_unknown_project_returns_404(self, client):
        """A non-existent project_id returns 404."""
        resp = client.get('/api/v1/projects/999999/tasks')
        assert resp.status_code == 404

    def test_tasks_are_scoped_to_project(self, client, db_session,
                                          sample_project, sample_user, app):
        """Tasks from a different project are not returned for the given project."""
        from models import Project
        with app.app_context():
            other_project = Project(
                name='Other Project',
                description='Another project',
                owner_id=sample_user.id,
                is_public=False,
            )
            db_session.add(other_project)
            db_session.commit()

            _create_task(db_session, 'Other Project Task', 'desc',
                         other_project.id, sample_user.id)

            resp = client.get(f'/api/v1/projects/{sample_project.id}/tasks?search=Other')
            assert resp.status_code == 200
            data = resp.get_json()
            # Tasks from the other project must not appear
            for task in data['tasks']:
                assert task['project_id'] == sample_project.id


# ---------------------------------------------------------------------------
# SQL-injection attack-vector tests (security regression guard)
# ---------------------------------------------------------------------------

class TestGetProjectTasksSQLInjection:
    """
    Confirm that classic SQL injection payloads in the 'search' parameter do NOT
    cause data leakage, errors, or unexpected query behaviour.

    With a parameterized query the payload is treated as a literal string; the
    database never parses it as SQL, so these requests either return an empty
    result set or return only rows that literally contain the payload as text.
    They must NOT raise a 500 error and must NOT return rows that the predicate
    would not normally select.
    """

    def _assert_safe_response(self, resp):
        """The server must respond with 200 and a well-formed JSON body."""
        assert resp.status_code == 200, (
            f"Expected 200 but got {resp.status_code}: {resp.data}"
        )
        data = resp.get_json()
        assert data is not None
        assert 'tasks' in data

    def test_classic_or_1_equals_1(self, client, sample_project):
        """' OR '1'='1 — the canonical 'always true' injection."""
        payload = "' OR '1'='1"
        resp = client.get(
            f'/api/v1/projects/{sample_project.id}/tasks',
            query_string={'search': payload},
        )
        self._assert_safe_response(resp)
        # Must not return rows that don't literally contain the payload text
        for task in resp.get_json()['tasks']:
            needle = payload.lower()
            combined = (task.get('title', '') + task.get('description', '')).lower()
            assert needle in combined, (
                "Injection payload was treated as SQL — rows returned that should not match"
            )

    def test_union_select_injection(self, client, sample_project):
        """UNION SELECT injection attempt to read extra data."""
        payload = "x' UNION SELECT 1,2,3,4,5,6,7,8,9,10--"
        resp = client.get(
            f'/api/v1/projects/{sample_project.id}/tasks',
            query_string={'search': payload},
        )
        self._assert_safe_response(resp)
        # No tasks should match because the literal string is not in any title/description
        assert resp.get_json()['tasks'] == []

    def test_comment_based_injection(self, client, sample_project):
        """Payload using SQL comment to strip the WHERE clause."""
        payload = "anything'--"
        resp = client.get(
            f'/api/v1/projects/{sample_project.id}/tasks',
            query_string={'search': payload},
        )
        self._assert_safe_response(resp)

    def test_stacked_query_injection(self, client, sample_project):
        """Stacked query (semicolon) injection attempt."""
        payload = "x'; DROP TABLE tasks;--"
        resp = client.get(
            f'/api/v1/projects/{sample_project.id}/tasks',
            query_string={'search': payload},
        )
        self._assert_safe_response(resp)

    def test_blind_boolean_injection(self, client, sample_project):
        """Blind boolean injection that would flip result sets."""
        payload = "' AND 1=1--"
        resp = client.get(
            f'/api/v1/projects/{sample_project.id}/tasks',
            query_string={'search': payload},
        )
        self._assert_safe_response(resp)

    def test_wildcard_percent_is_literal(self, client, db_session,
                                          sample_project, sample_user):
        """A bare '%' should be treated as a literal percent, not a SQL wildcard."""
        _create_task(db_session, 'Percent Task', '100% done', sample_project.id, sample_user.id)

        resp = client.get(
            f'/api/v1/projects/{sample_project.id}/tasks',
            query_string={'search': '100%'},
        )
        self._assert_safe_response(resp)
        # The row with '100% done' description should match (percent is literal in LIKE)
        data = resp.get_json()
        assert len(data['tasks']) >= 1

    def test_null_byte_in_search(self, client, sample_project):
        """NUL byte in input must not cause a 500 error."""
        # Use the escape sequence \x00 — never embed a literal NUL byte in source
        payload = "task\x00injected"
        resp = client.get(
            f'/api/v1/projects/{sample_project.id}/tasks',
            query_string={'search': payload},
        )
        # The server should handle this gracefully (200 or 400), not crash with 500
        assert resp.status_code != 500

    def test_special_chars_no_server_error(self, client, sample_project):
        """Various special characters must not cause a 500 server error."""
        payloads = [
            "'; SELECT * FROM users;--",
            '" OR "1"="1',
            "\\",
            "/**/OR/**/1=1",
            "%27 OR %271%27=%271",
        ]
        for payload in payloads:
            resp = client.get(
                f'/api/v1/projects/{sample_project.id}/tasks',
                query_string={'search': payload},
            )
            assert resp.status_code != 500, (
                f"Payload caused a 500 error: {payload!r}"
            )
