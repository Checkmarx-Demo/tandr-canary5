"""
Basic tests for utility functions
"""
import unittest
import sys
import os
import json
import tempfile
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.datetime_utils import get_utc_now, format_utc_datetime, get_utc_timestamp


class TestDateTimeUtils(unittest.TestCase):
    """Test datetime utility functions"""
    
    def test_get_utc_now(self):
        """Test get_utc_now returns datetime"""
        result = get_utc_now()
        self.assertIsInstance(result, datetime)
    
    def test_get_utc_timestamp(self):
        """Test get_utc_timestamp returns float"""
        result = get_utc_timestamp()
        self.assertIsInstance(result, float)
        self.assertGreater(result, 0)
    
    def test_format_utc_datetime_default(self):
        """Test format_utc_datetime with default (current time)"""
        result = format_utc_datetime()
        self.assertIsInstance(result, str)
        # ISO format should contain 'T'
        self.assertIn('T', result)
    
    def test_format_utc_datetime_with_value(self):
        """Test format_utc_datetime with specific datetime"""
        dt = datetime(2023, 12, 25, 15, 30, 45)
        result = format_utc_datetime(dt)
        self.assertIsInstance(result, str)
        self.assertIn('2023', result)
        self.assertIn('12', result)
        self.assertIn('25', result)


class TestStringUtils(unittest.TestCase):
    """Test basic string utilities"""
    
    def test_string_truncation_logic(self):
        """Test basic truncation logic"""
        text = "This is a very long text that should be truncated"
        max_length = 20
        
        if len(text) > max_length:
            truncated = text[:max_length] + '...'
        else:
            truncated = text
        
        self.assertEqual(len(truncated), 23)  # 20 + "..."
        self.assertTrue(truncated.endswith('...'))
    
    def test_file_size_calculation(self):
        """Test file size calculation logic"""
        # Test bytes
        size = 500
        self.assertLess(size, 1024)
        
        # Test KB
        size_kb = 1500
        kb_value = size_kb / 1024.0
        self.assertGreater(kb_value, 1.0)
        self.assertLess(kb_value, 1024.0)


class TestProcessPickleFile(unittest.TestCase):
    """Tests for process_pickle_file — CWE-502 deserialization remediation.

    The function previously used pickle.load() on the supplied file, which
    allows arbitrary code execution.  It now refuses to deserialize pickle
    data and only accepts JSON-encoded content.
    """

    def setUp(self):
        """Create a temporary directory for test files."""
        from utils.file_handler import process_pickle_file
        self.process_pickle_file = process_pickle_file
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        """Remove temporary files created during the test."""
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Positive path: valid JSON content in a .pkl-named file is accepted
    # ------------------------------------------------------------------

    def test_valid_json_dict_is_returned(self):
        """JSON-encoded dict in a .pkl file is parsed and returned."""
        payload = {"key": "value", "count": 42}
        path = os.path.join(self.tmpdir, "data.pkl")
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f)

        result = self.process_pickle_file(path)
        self.assertEqual(result, payload)

    def test_valid_json_list_is_returned(self):
        """JSON-encoded list is parsed correctly."""
        payload = [1, 2, 3, "hello"]
        path = os.path.join(self.tmpdir, "data.pickle")
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f)

        result = self.process_pickle_file(path)
        self.assertEqual(result, payload)

    def test_valid_json_nested_structure(self):
        """Nested JSON structure is parsed correctly."""
        payload = {"outer": {"inner": [1, 2, 3]}, "flag": True}
        path = os.path.join(self.tmpdir, "nested.pkl")
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(payload, f)

        result = self.process_pickle_file(path)
        self.assertEqual(result, payload)

    # ------------------------------------------------------------------
    # Security: actual pickle payloads must NOT be deserialized
    # ------------------------------------------------------------------

    def test_pickle_binary_payload_is_rejected(self):
        """A real pickle binary payload must NOT be deserialized (CWE-502).

        Verifies that process_pickle_file returns an error dict rather than
        executing any code embedded in the pickle stream.
        """
        import pickle as _pickle

        # Build an innocent pickled object (a plain dict).
        # Even innocent pickle data must be rejected to close the attack surface.
        innocent_data = {"safe": True}
        pickle_bytes = _pickle.dumps(innocent_data)

        path = os.path.join(self.tmpdir, "legit.pkl")
        with open(path, 'wb') as f:
            f.write(pickle_bytes)

        result = self.process_pickle_file(path)

        # Must return an error, NOT the deserialized object
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)
        # The deserialized value must never be returned
        self.assertNotEqual(result, innocent_data)

    def test_malicious_pickle_rce_payload_is_rejected(self):
        """A pickle payload crafted to run os.system must never execute.

        This test constructs a malicious pickle opcode sequence that would
        call os.getpid() (a harmless stand-in for os.system) and verifies
        it is rejected before any deserialization occurs.
        """
        import pickle as _pickle
        import io

        # Craft a pickle that would call os.getpid when deserialized
        class _MaliciousPayload:
            def __reduce__(self):
                return (os.getpid, ())

        malicious_bytes = _pickle.dumps(_MaliciousPayload())

        path = os.path.join(self.tmpdir, "evil.pkl")
        with open(path, 'wb') as f:
            f.write(malicious_bytes)

        result = self.process_pickle_file(path)

        # Must return an error dict; the callable must not have been invoked
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)
        # os.getpid() returns an int; the result must not be an int
        self.assertNotIsInstance(result, int)

    def test_pickle_opcode_bytes_produce_error_not_data(self):
        """Raw pickle opcodes written to a file must yield an error response."""
        # Minimal pickle opcode: MARK + EMPTY_DICT + STOP — equivalent to {}
        # (pickle protocol 0, entirely printable bytes)
        raw_pickle = b'\x80\x04\x95\x0f\x00\x00\x00\x00\x00\x00\x00}\x94.'

        path = os.path.join(self.tmpdir, "opcodes.pkl")
        with open(path, 'wb') as f:
            f.write(raw_pickle)

        result = self.process_pickle_file(path)

        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    # ------------------------------------------------------------------
    # Error handling: missing / invalid files
    # ------------------------------------------------------------------

    def test_missing_file_returns_error(self):
        """A non-existent file path returns an error dict."""
        path = os.path.join(self.tmpdir, "does_not_exist.pkl")
        result = self.process_pickle_file(path)

        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    def test_invalid_json_content_returns_error(self):
        """A text file with invalid JSON returns an informative error."""
        path = os.path.join(self.tmpdir, "bad.pkl")
        with open(path, 'w', encoding='utf-8') as f:
            f.write("this is not json }{")

        result = self.process_pickle_file(path)

        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    def test_empty_file_returns_error(self):
        """An empty file (cannot be valid JSON) returns an error dict."""
        path = os.path.join(self.tmpdir, "empty.pkl")
        open(path, 'w').close()

        result = self.process_pickle_file(path)

        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    # ------------------------------------------------------------------
    # Verify pickle module is NOT imported by file_handler
    # ------------------------------------------------------------------

    def test_pickle_not_imported_in_file_handler(self):
        """The file_handler module must not import the pickle module.

        Importing pickle is not itself dangerous, but it signals the sink
        is still present.  Removing the import confirms the sink is gone.
        """
        import utils.file_handler as fh
        self.assertFalse(
            hasattr(fh, 'pickle'),
            "utils.file_handler must not expose the 'pickle' module"
        )


if __name__ == '__main__':
    unittest.main()

