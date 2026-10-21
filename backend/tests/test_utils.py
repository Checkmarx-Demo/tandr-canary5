"""
Basic tests for utility functions
"""
import unittest
import sys
import os
import io
from datetime import datetime
from unittest.mock import MagicMock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.datetime_utils import get_utc_now, format_utc_datetime, get_utc_timestamp
from utils.file_handler import allowed_file, save_uploaded_file
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
    """Tests for CWE-434: Unrestricted Upload of File with Dangerous Type remediation.

    Verifies that the ALLOWED_EXTENSIONS allowlist excludes dangerous executable
    types and that save_uploaded_file enforces the allowlist before persisting.
    """

    # --- Dangerous extensions that MUST be blocked ---

    def test_php_extension_rejected(self):
        """PHP scripts must not be uploadable (remote code execution risk)"""
        self.assertFalse(allowed_file("shell.php"))

    def test_exe_extension_rejected(self):
        """Windows executables must not be uploadable"""
        self.assertFalse(allowed_file("malware.exe"))

    def test_sh_extension_rejected(self):
        """Shell scripts must not be uploadable"""
        self.assertFalse(allowed_file("backdoor.sh"))

    def test_php_not_in_allowed_extensions_config(self):
        """Config.ALLOWED_EXTENSIONS must not contain php"""
        self.assertNotIn('php', Config.ALLOWED_EXTENSIONS)

    def test_exe_not_in_allowed_extensions_config(self):
        """Config.ALLOWED_EXTENSIONS must not contain exe"""
        self.assertNotIn('exe', Config.ALLOWED_EXTENSIONS)

    def test_sh_not_in_allowed_extensions_config(self):
        """Config.ALLOWED_EXTENSIONS must not contain sh"""
        self.assertNotIn('sh', Config.ALLOWED_EXTENSIONS)

    # --- Legitimate extensions that MUST still be allowed ---

    def test_txt_extension_allowed(self):
        """Plain text files should be uploadable"""
        self.assertTrue(allowed_file("readme.txt"))

    def test_pdf_extension_allowed(self):
        """PDF files should be uploadable"""
        self.assertTrue(allowed_file("report.pdf"))

    def test_png_extension_allowed(self):
        """PNG images should be uploadable"""
        self.assertTrue(allowed_file("image.png"))

    def test_jpg_extension_allowed(self):
        """JPEG images should be uploadable"""
        self.assertTrue(allowed_file("photo.jpg"))

    def test_jpeg_extension_allowed(self):
        """JPEG images (.jpeg) should be uploadable"""
        self.assertTrue(allowed_file("photo.jpeg"))

    def test_gif_extension_allowed(self):
        """GIF images should be uploadable"""
        self.assertTrue(allowed_file("anim.gif"))

    def test_docx_extension_allowed(self):
        """Word documents should be uploadable"""
        self.assertTrue(allowed_file("doc.docx"))

    def test_xml_extension_allowed(self):
        """XML files should be uploadable"""
        self.assertTrue(allowed_file("data.xml"))

    # --- Edge cases ---

    def test_no_extension_rejected(self):
        """Files without an extension must be rejected"""
        self.assertFalse(allowed_file("noextension"))

    def test_empty_filename_rejected(self):
        """Empty filename must be rejected"""
        self.assertFalse(allowed_file(""))

    def test_dot_only_rejected(self):
        """Filename that is just a dot must be rejected"""
        self.assertFalse(allowed_file("."))

    def test_case_insensitive_rejection(self):
        """Extension check should be case-insensitive; uppercase PHP must be blocked"""
        self.assertFalse(allowed_file("shell.PHP"))

    def test_case_insensitive_rejection_exe(self):
        """Extension check should be case-insensitive; uppercase EXE must be blocked"""
        self.assertFalse(allowed_file("virus.EXE"))

    def test_double_extension_dangerous(self):
        """Double-extension filename with dangerous final extension must be blocked"""
        # e.g. image.png.php — rsplit('.', 1) picks up 'php'
        self.assertFalse(allowed_file("image.png.php"))

    def test_double_extension_safe_final(self):
        """Double-extension filename whose final extension is safe is allowed"""
        # e.g. archive.php.txt — final extension is txt which is allowed
        self.assertTrue(allowed_file("archive.php.txt"))


class TestSaveUploadedFileValidation(unittest.TestCase):
    """Tests that save_uploaded_file enforces the file-type allowlist."""

    def _make_mock_file(self, filename):
        """Helper to create a mock Flask FileStorage object."""
        mock_file = MagicMock()
        mock_file.filename = filename
        return mock_file

    def test_save_rejects_php_file(self):
        """save_uploaded_file must reject PHP uploads and return an error."""
        mock_file = self._make_mock_file("shell.php")
        result, error = save_uploaded_file(mock_file)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        # Ensure .save() was never called — the file must not reach disk
        mock_file.save.assert_not_called()

    def test_save_rejects_exe_file(self):
        """save_uploaded_file must reject EXE uploads and return an error."""
        mock_file = self._make_mock_file("trojan.exe")
        result, error = save_uploaded_file(mock_file)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        mock_file.save.assert_not_called()

    def test_save_rejects_sh_file(self):
        """save_uploaded_file must reject shell script uploads."""
        mock_file = self._make_mock_file("backdoor.sh")
        result, error = save_uploaded_file(mock_file)
        self.assertIsNone(result)
        self.assertIsNotNone(error)
        mock_file.save.assert_not_called()

    def test_save_rejects_empty_filename(self):
        """save_uploaded_file must reject files with no filename."""
        mock_file = MagicMock()
        mock_file.filename = ""
        result, error = save_uploaded_file(mock_file)
        self.assertIsNone(result)
        self.assertIsNotNone(error)

    def test_save_rejects_none_file(self):
        """save_uploaded_file must reject None input."""
        result, error = save_uploaded_file(None)
        self.assertIsNone(result)
        self.assertIsNotNone(error)

    @patch('utils.file_handler.os.path.getsize', return_value=1024)
    @patch('utils.file_handler.get_file_type', return_value='text/plain')
    @patch('utils.file_handler.os.chmod')
    @patch('utils.file_handler.os.path.join', return_value='/tmp/test_uploads/test.txt')
    def test_save_accepts_txt_file(self, mock_join, mock_chmod, mock_get_type, mock_getsize):
        """save_uploaded_file should accept .txt files and call file.save()."""
        mock_file = self._make_mock_file("document.txt")
        # Patch Config.UPLOAD_FOLDER to avoid actual directory dependency
        with patch.object(Config, 'UPLOAD_FOLDER', '/tmp/test_uploads'):
            result, error = save_uploaded_file(mock_file)
        self.assertIsNone(error)
        self.assertIsNotNone(result)
        mock_file.save.assert_called_once()


if __name__ == '__main__':
    unittest.main()

