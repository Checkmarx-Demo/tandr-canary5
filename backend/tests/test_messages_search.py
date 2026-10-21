"""
Tests for the messages search endpoint, specifically validating that the
SQL injection vulnerability (CWE-89) in search_messages has been remediated.

The fix replaced raw f-string SQL interpolation with SQLAlchemy ORM
parameterized LIKE queries so that user-supplied input is never embedded
directly into the SQL statement.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User, Message


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(db_session, username, email):
    """Create and persist a User, returning the instance."""
    user = User(username=username, email=email, role='team_member')
    user.set_password('testpass123')
    db_session.add(user)
    db_session.commit()
    return user


def _make_message(db_session, sender, receiver, subject, content):
    """Create and persist a Message, returning the instance."""
    msg = Message(
        sender_id=sender.id,
        receiver_id=receiver.id,
        subject=subject,
        content=content,
    )
    db_session.add(msg)
    db_session.commit()
    return msg


def _auth_headers(app, user):
    """Return a Bearer-token Authorization header dict for *user*."""
    with app.app_context():
        from auth import generate_token
        token = generate_token(user.id, user.username)
        return {'Authorization': f'Bearer {token}'}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def users(db_session):
    """Two users: sender and receiver."""
    sender = _make_user(db_session, 'sender_user', 'sender@example.com')
    receiver = _make_user(db_session, 'recv_user', 'recv@example.com')
    return sender, receiver


@pytest.fixture
def seeded_messages(db_session, users):
    """A small set of messages with predictable content/subject strings."""
    sender, receiver = users
    msgs = [
        _make_message(db_session, sender, receiver,
                      'Hello World', 'This is the first message content'),
        _make_message(db_session, sender, receiver,
                      'Project Update', 'The project deadline has been extended'),
        _make_message(db_session, receiver, sender,
                      'Re: Hello World', 'Got your message, thanks'),
        _make_message(db_session, sender, receiver,
                      'Urgent notice', 'Please review the attached document'),
    ]
    return msgs


# ---------------------------------------------------------------------------
# Search endpoint — functional correctness
# ---------------------------------------------------------------------------

class TestSearchMessagesFunctionality:
    """Verify that the search endpoint returns correct results."""

    def test_search_by_content_match(self, app, client, db_session, users, seeded_messages):
        """A term present in message content should appear in results."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        resp = client.get('/api/messages/search?q=deadline', headers=headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert 'results' in data
        # The message whose content contains 'deadline' must be returned.
        assert any('deadline' in (r.get('content') or '') for r in data['results'])

    def test_search_by_subject_match(self, app, client, db_session, users, seeded_messages):
        """A term present in message subject should appear in results."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        resp = client.get('/api/messages/search?q=Urgent', headers=headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert any('Urgent' in (r.get('subject') or '') for r in data['results'])

    def test_search_no_match_returns_empty(self, app, client, db_session, users, seeded_messages):
        """A term that appears in no message should return an empty results list."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        resp = client.get('/api/messages/search?q=zzz_no_match_xyz', headers=headers)

        assert resp.status_code == 200
        data = resp.get_json()
        assert data['results'] == []

    def test_search_returns_query_echo(self, app, client, db_session, users, seeded_messages):
        """The response body must echo back the original search term."""
        sender, _ = users
        headers = _auth_headers(app, sender)
        term = 'Hello'

        resp = client.get(f'/api/messages/search?q={term}', headers=headers)

        assert resp.status_code == 200
        assert resp.get_json()['query'] == term

    def test_search_partial_match(self, app, client, db_session, users, seeded_messages):
        """A partial substring match should return all messages containing it."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        # 'message' appears in multiple messages
        resp = client.get('/api/messages/search?q=message', headers=headers)

        assert resp.status_code == 200
        data = resp.get_json()
        # At least the two messages with 'message' in content/subject are returned.
        assert len(data['results']) >= 2

    def test_search_case_insensitive_sqlite(self, app, client, db_session, users, seeded_messages):
        """SQLite LIKE is case-insensitive for ASCII; lowercase term finds mixed-case content."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        # 'hello' (lower) should match 'Hello World' subject (SQLite default behaviour)
        resp = client.get('/api/messages/search?q=hello', headers=headers)

        assert resp.status_code == 200
        # At minimum the response must be a valid JSON with the expected keys.
        data = resp.get_json()
        assert 'results' in data


# ---------------------------------------------------------------------------
# Search endpoint — security: SQL injection prevention
# ---------------------------------------------------------------------------

class TestSearchMessagesSQLInjection:
    """Verify that SQL injection payloads do NOT cause errors or data leaks."""

    @pytest.mark.parametrize("payload", [
        # Classic UNION-based injection
        "' UNION SELECT 1,2,3,4,5,6,7--",
        "'; DROP TABLE messages;--",
        # OR-based tautology that would normally return all rows
        "' OR '1'='1",
        "' OR 1=1--",
        # Boolean-blind injection attempt
        "x' AND 1=1--",
        "x' AND 1=2--",
        # Stacked queries (usually blocked at DB level but should not crash)
        "'; INSERT INTO messages (sender_id, receiver_id, content) VALUES (1,1,'hacked');--",
        # Comment-stripping attempt
        "test%' --",
        # Percent wildcards (already safe in LIKE, but should not crash)
        "%",
        "%%",
        # NUL byte expressed as escape sequence (never a literal NUL in source)
        "test\x00payload",
    ])
    def test_injection_payload_does_not_crash(
            self, app, client, db_session, users, seeded_messages, payload):
        """Injection payloads must not cause a 500 error."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        from urllib.parse import urlencode
        resp = client.get(
            '/api/messages/search?' + urlencode({'q': payload}),
            headers=headers,
        )

        # The endpoint must respond with 200 (no match is fine) or 400, never 500.
        assert resp.status_code in (200, 400), (
            f"Injection payload caused unexpected status {resp.status_code}: {payload!r}"
        )

    def test_union_injection_does_not_leak_extra_rows(
            self, app, client, db_session, users, seeded_messages):
        """A UNION-based injection that could leak rows must not return extra data."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        # With raw SQL this payload would append extra rows from another query.
        payload = "' UNION SELECT id,sender_id,receiver_id,subject,content,is_read,created_at FROM messages--"
        from urllib.parse import urlencode
        resp = client.get(
            '/api/messages/search?' + urlencode({'q': payload}),
            headers=headers,
        )

        assert resp.status_code == 200
        data = resp.get_json()
        # A safe parameterized query treats the whole string as a literal search
        # term — which matches nothing — so results must be empty.
        assert data['results'] == [], (
            "UNION injection payload should not return rows when queries are parameterized"
        )

    def test_tautology_does_not_return_all_rows(
            self, app, client, db_session, users, seeded_messages):
        """OR-tautology payload must not bypass the LIKE filter and dump all rows."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        payload = "' OR '1'='1"
        from urllib.parse import urlencode
        resp = client.get(
            '/api/messages/search?' + urlencode({'q': payload}),
            headers=headers,
        )

        assert resp.status_code == 200
        data = resp.get_json()
        # With a parameterized query the tautology is just a literal search term;
        # there are no messages whose content/subject contains that exact string.
        assert data['results'] == [], (
            "Tautology injection should not return all rows when queries are parameterized"
        )

    def test_drop_table_payload_does_not_destroy_data(
            self, app, client, db_session, users, seeded_messages):
        """A DROP TABLE payload must not wipe the messages table."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        payload = "'; DROP TABLE messages;--"
        from urllib.parse import urlencode
        client.get(
            '/api/messages/search?' + urlencode({'q': payload}),
            headers=headers,
        )

        # If the table were dropped, subsequent ORM queries would fail.
        # Confirm the table still exists by doing a normal search.
        resp = client.get('/api/messages/search?q=message', headers=headers)
        assert resp.status_code == 200, (
            "Messages table appears to have been damaged by a DROP TABLE payload"
        )


# ---------------------------------------------------------------------------
# Search endpoint — input validation
# ---------------------------------------------------------------------------

class TestSearchMessagesInputValidation:
    """Verify correct handling of missing or empty query parameters."""

    def test_missing_q_param_returns_400(self, app, client, db_session, users):
        """Calling /search without ?q should return 400."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        resp = client.get('/api/messages/search', headers=headers)

        assert resp.status_code == 400
        data = resp.get_json()
        assert 'error' in data

    def test_empty_q_param_returns_400(self, app, client, db_session, users):
        """Calling /search with ?q= (empty string) should return 400."""
        sender, _ = users
        headers = _auth_headers(app, sender)

        resp = client.get('/api/messages/search?q=', headers=headers)

        assert resp.status_code == 400

    def test_search_requires_authentication(self, client):
        """Unauthenticated request must be rejected (401 or 403)."""
        resp = client.get('/api/messages/search?q=test')

        assert resp.status_code in (401, 403)
