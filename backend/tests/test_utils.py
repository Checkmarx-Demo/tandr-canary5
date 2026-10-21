"""
Basic tests for utility functions
"""
import unittest
import sys
import os
import io
from unittest.mock import MagicMock, patch
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.datetime_utils import get_utc_now, format_utc_datetime, get_utc_timestamp
from utils.file_handler import allowed_file
from config import Config


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


class TestAllowedFileExtensions(unittest.TestCase):
    """Tests for CWE-434 remediation: Unrestricted Upload of File with Dangerous Type.

    The fix removes dangerous types (php, exe, sh, xml) from ALLOWED_EXTENSIONS
    and enforces the allowlist check inside save_uploaded_file() before writing
    anything to disk.
    """

    # ------------------------------------------------------------------ #
    # Config-level: verify the allowlist itself contains no dangerous types
    # ------------------------------------------------------------------ #

    def test_dangerous_extensions_absent_from_allowlist(self):
        """Dangerous executable/server-side types must not be in ALLOWED_EXTENSIONS."""
        dangerous = {'php', 'exe', 'sh', 'bat', 'cmd', 'py', 'rb', 'pl', 'cgi'}
        overlap = dangerous & Config.ALLOWED_EXTENSIONS
        self.assertEqual(
            overlap, set(),
            f"Dangerous extensions still in ALLOWED_EXTENSIONS: {overlap}"
        )

    def test_xml_absent_from_allowlist(self):
        """XML files are dangerous (XXE) and must not be in ALLOWED_EXTENSIONS."""
        self.assertNotIn('xml', Config.ALLOWED_EXTENSIONS)

    def test_safe_extensions_present_in_allowlist(self):
        """Common safe document/image types must remain allowed."""
        safe = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}
        for ext in safe:
            self.assertIn(ext, Config.ALLOWED_EXTENSIONS,
                          f"Safe extension '{ext}' unexpectedly removed from allowlist")

    # ------------------------------------------------------------------ #
    # allowed_file() unit tests
    # ------------------------------------------------------------------ #

    def test_allowed_file_returns_true_for_safe_extensions(self):
        """allowed_file() must accept files with safe extensions."""
        safe_filenames = [
            'report.pdf', 'image.png', 'photo.jpg', 'photo.jpeg',
            'animation.gif', 'notes.txt', 'document.docx',
        ]
        for name in safe_filenames:
            with self.subTest(filename=name):
                self.assertTrue(allowed_file(name),
                                f"allowed_file() incorrectly rejected safe file: {name}")

    def test_allowed_file_returns_false_for_php(self):
        """allowed_file() must reject PHP scripts."""
        self.assertFalse(allowed_file('shell.php'))
        self.assertFalse(allowed_file('webshell.PHP'))  # case-insensitive check

    def test_allowed_file_returns_false_for_exe(self):
        """allowed_file() must reject Windows executables."""
        self.assertFalse(allowed_file('malware.exe'))

    def test_allowed_file_returns_false_for_shell_scripts(self):
        """allowed_file() must reject shell scripts."""
        self.assertFalse(allowed_file('exploit.sh'))

    def test_allowed_file_returns_false_for_xml(self):
        """allowed_file() must reject XML files (potential XXE vectors)."""
        self.assertFalse(allowed_file('payload.xml'))

    def test_allowed_file_returns_false_for_no_extension(self):
        """allowed_file() must reject filenames with no extension."""
        self.assertFalse(allowed_file('noextension'))

    def test_allowed_file_returns_false_for_empty_filename(self):
        """allowed_file() must reject empty filenames."""
        self.assertFalse(allowed_file(''))

    def test_allowed_file_case_insensitive(self):
        """allowed_file() extension check must be case-insensitive."""
        self.assertTrue(allowed_file('image.PNG'))
        self.assertTrue(allowed_file('document.PDF'))
        self.assertFalse(allowed_file('script.SH'))
        self.assertFalse(allowed_file('virus.EXE'))

    def test_allowed_file_double_extension_attack(self):
        """allowed_file() must use the LAST extension to defeat double-extension tricks."""
        # 'shell.php.txt' → last extension is 'txt' → should be allowed
        self.assertTrue(allowed_file('shell.php.txt'))
        # 'image.jpg.php' → last extension is 'php' → must be rejected
        self.assertFalse(allowed_file('image.jpg.php'))

    # ------------------------------------------------------------------ #
    # save_uploaded_file() unit tests (enforce allowlist before disk write)
    # ------------------------------------------------------------------ #

    def _make_mock_file(self, filename, content=b'test content'):
        """Return a mock Werkzeug FileStorage with the given filename."""
        mock_file = MagicMock()
        mock_file.filename = filename
        mock_file.save = MagicMock()
        return mock_file

    @patch('utils.file_handler.os.path.getsize', return_value=100)
    @patch('utils.file_handler.os.chmod')
    @patch('utils.file_handler.get_file_type', return_value='text/plain')
    def test_save_uploaded_file_accepts_safe_file(
        self, mock_get_type, mock_chmod, mock_getsize
    ):
        """save_uploaded_file() must succeed for files with safe extensions."""
        from utils.file_handler import save_uploaded_file
        mock_file = self._make_mock_file('report.pdf')

        with patch('utils.file_handler.os.path.join', return_value='/tmp/test_uploads/uuid_report.pdf'):
            file_info, error = save_uploaded_file(mock_file)

        self.assertIsNone(error, f"Expected no error for safe file, got: {error}")
        self.assertIsNotNone(file_info)

    def test_save_uploaded_file_rejects_php(self):
        """save_uploaded_file() must reject PHP files without touching the disk."""
        from utils.file_handler import save_uploaded_file
        mock_file = self._make_mock_file('shell.php')

        file_info, error = save_uploaded_file(mock_file)

        self.assertIsNone(file_info)
        self.assertIsNotNone(error)
        self.assertIn('not allowed', error.lower())
        # Verify .save() was never called — no bytes written to disk
        mock_file.save.assert_not_called()

    def test_save_uploaded_file_rejects_exe(self):
        """save_uploaded_file() must reject executable binaries."""
        from utils.file_handler import save_uploaded_file
        mock_file = self._make_mock_file('malware.exe')

        file_info, error = save_uploaded_file(mock_file)

        self.assertIsNone(file_info)
        self.assertIsNotNone(error)
        mock_file.save.assert_not_called()

    def test_save_uploaded_file_rejects_shell_script(self):
        """save_uploaded_file() must reject shell scripts."""
        from utils.file_handler import save_uploaded_file
        mock_file = self._make_mock_file('exploit.sh')

        file_info, error = save_uploaded_file(mock_file)

        self.assertIsNone(file_info)
        self.assertIsNotNone(error)
        mock_file.save.assert_not_called()

    def test_save_uploaded_file_rejects_xml(self):
        """save_uploaded_file() must reject XML uploads."""
        from utils.file_handler import save_uploaded_file
        mock_file = self._make_mock_file('xxe_payload.xml')

        file_info, error = save_uploaded_file(mock_file)

        self.assertIsNone(file_info)
        self.assertIsNotNone(error)
        mock_file.save.assert_not_called()

    def test_save_uploaded_file_rejects_no_filename(self):
        """save_uploaded_file() must reject calls with no filename."""
        from utils.file_handler import save_uploaded_file
        mock_file = self._make_mock_file('')

        file_info, error = save_uploaded_file(mock_file)

        self.assertIsNone(file_info)
        self.assertIsNotNone(error)

    def test_save_uploaded_file_rejects_none_file(self):
        """save_uploaded_file() must reject a None file object."""
        from utils.file_handler import save_uploaded_file

        file_info, error = save_uploaded_file(None)

        self.assertIsNone(file_info)
        self.assertIsNotNone(error)


if __name__ == '__main__':
    unittest.main()

