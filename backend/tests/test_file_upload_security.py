"""
Security tests for file upload restrictions (CWE-434).

Verifies that:
1. Dangerous executable extensions are blocked by the allowlist in Config.
2. safe_uploaded_file enforces the allowlist before saving.
3. Legitimate document/image extensions remain accepted.
"""
import io
import sys
import os
import unittest

# Make sure the backend package is importable regardless of how pytest is invoked
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from utils.file_handler import allowed_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_werkzeug_file(filename: str, content: bytes = b"test content"):
    """Return a minimal Werkzeug FileStorage-like object."""
    from werkzeug.datastructures import FileStorage
    return FileStorage(
        stream=io.BytesIO(content),
        filename=filename,
        content_type="application/octet-stream",
    )


# ---------------------------------------------------------------------------
# Unit tests for Config.ALLOWED_EXTENSIONS
# ---------------------------------------------------------------------------

class TestAllowedExtensionsConfig(unittest.TestCase):
    """Ensure the allowlist in Config contains only safe file types."""

    DANGEROUS_EXTENSIONS = {'php', 'exe', 'sh', 'bat', 'cmd', 'com', 'pif',
                            'vbs', 'js', 'py', 'pl', 'rb', 'cgi', 'asp',
                            'aspx', 'jsp', 'phtml', 'shtml'}

    def test_php_not_allowed(self):
        """PHP files must not be in the allowlist (remote code execution risk)."""
        self.assertNotIn('php', Config.ALLOWED_EXTENSIONS,
                         "php is a dangerous extension and must NOT be in ALLOWED_EXTENSIONS")

    def test_exe_not_allowed(self):
        """Executable binaries must not be in the allowlist."""
        self.assertNotIn('exe', Config.ALLOWED_EXTENSIONS,
                         "exe is a dangerous extension and must NOT be in ALLOWED_EXTENSIONS")

    def test_shell_script_not_allowed(self):
        """Shell scripts must not be in the allowlist."""
        self.assertNotIn('sh', Config.ALLOWED_EXTENSIONS,
                         "sh is a dangerous extension and must NOT be in ALLOWED_EXTENSIONS")

    def test_no_dangerous_extensions_present(self):
        """None of the known dangerous extensions should appear in the allowlist."""
        found = Config.ALLOWED_EXTENSIONS & self.DANGEROUS_EXTENSIONS
        self.assertEqual(found, set(),
                         f"Dangerous extension(s) found in ALLOWED_EXTENSIONS: {found}")

    def test_safe_extensions_present(self):
        """Common safe document/image extensions should still be allowed."""
        safe = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}
        missing = safe - Config.ALLOWED_EXTENSIONS
        self.assertEqual(missing, set(),
                         f"Safe extension(s) unexpectedly removed from ALLOWED_EXTENSIONS: {missing}")


# ---------------------------------------------------------------------------
# Unit tests for allowed_file()
# ---------------------------------------------------------------------------

class TestAllowedFileFunction(unittest.TestCase):
    """Test the allowed_file() helper against safe and dangerous filenames."""

    # Safe names that should pass
    SAFE_FILENAMES = [
        'report.pdf',
        'photo.png',
        'picture.jpg',
        'image.jpeg',
        'animation.gif',
        'notes.txt',
        'document.docx',
    ]

    # Dangerous names that must be rejected
    DANGEROUS_FILENAMES = [
        'shell.php',
        'malware.exe',
        'exploit.sh',
        'script.bat',
        'backdoor.cmd',
        # Double-extension evasion attempts
        'legit.pdf.php',
        'image.png.sh',
        'file.exe.jpg',   # extension checked is 'jpg' — allowed; but renamed .exe.jpg should still pass because the final extension is jpg
        # Note: 'file.exe' should be blocked
        'payload.exe',
        # Filename with no extension
        'noextension',
    ]

    def test_safe_files_are_allowed(self):
        """Safe document/image files must be accepted."""
        for name in self.SAFE_FILENAMES:
            with self.subTest(filename=name):
                self.assertTrue(allowed_file(name),
                                f"Expected '{name}' to be allowed but it was rejected")

    def test_php_rejected(self):
        self.assertFalse(allowed_file('webshell.php'))

    def test_exe_rejected(self):
        self.assertFalse(allowed_file('malware.exe'))

    def test_sh_rejected(self):
        self.assertFalse(allowed_file('exploit.sh'))

    def test_no_extension_rejected(self):
        self.assertFalse(allowed_file('noextension'))

    def test_empty_filename_rejected(self):
        self.assertFalse(allowed_file(''))

    def test_dot_only_filename_rejected(self):
        self.assertFalse(allowed_file('.'))


# ---------------------------------------------------------------------------
# Integration tests for save_uploaded_file()
# ---------------------------------------------------------------------------

class TestSaveUploadedFileEnforcement(unittest.TestCase):
    """Verify that save_uploaded_file rejects disallowed extensions."""

    def setUp(self):
        # Ensure the test upload folder exists
        os.makedirs('/tmp/test_uploads', exist_ok=True)
        # Patch Config.UPLOAD_FOLDER so no writes happen outside /tmp
        import config as cfg_module
        self._orig_folder = cfg_module.Config.UPLOAD_FOLDER
        cfg_module.Config.UPLOAD_FOLDER = '/tmp/test_uploads'

    def tearDown(self):
        import config as cfg_module
        cfg_module.Config.UPLOAD_FOLDER = self._orig_folder

    def _upload(self, filename: str):
        from utils.file_handler import save_uploaded_file
        fake_file = _make_werkzeug_file(filename)
        return save_uploaded_file(fake_file)

    def test_php_upload_rejected(self):
        """Uploading a .php file must return an error, not save the file."""
        file_info, error = self._upload('shell.php')
        self.assertIsNone(file_info, "file_info should be None for rejected uploads")
        self.assertIsNotNone(error, "An error message must be returned for rejected uploads")

    def test_exe_upload_rejected(self):
        """Uploading a .exe file must return an error."""
        file_info, error = self._upload('malware.exe')
        self.assertIsNone(file_info)
        self.assertIsNotNone(error)

    def test_sh_upload_rejected(self):
        """Uploading a .sh file must return an error."""
        file_info, error = self._upload('exploit.sh')
        self.assertIsNone(file_info)
        self.assertIsNotNone(error)

    def test_no_extension_rejected(self):
        """Files without an extension must be rejected."""
        file_info, error = self._upload('noextension')
        self.assertIsNone(file_info)
        self.assertIsNotNone(error)

    def test_pdf_upload_accepted(self):
        """Uploading a .pdf file should succeed (file saved, no error)."""
        file_info, error = self._upload('report.pdf')
        self.assertIsNone(error, f"Unexpected error for PDF upload: {error}")
        self.assertIsNotNone(file_info, "file_info should be populated for valid uploads")
        # Clean up
        if file_info and os.path.exists(file_info['file_path']):
            os.remove(file_info['file_path'])

    def test_png_upload_accepted(self):
        """Uploading a .png image should succeed."""
        file_info, error = self._upload('photo.png')
        self.assertIsNone(error, f"Unexpected error for PNG upload: {error}")
        self.assertIsNotNone(file_info)
        if file_info and os.path.exists(file_info['file_path']):
            os.remove(file_info['file_path'])

    def test_double_extension_exe_rejected(self):
        """Double-extension attack 'report.pdf.exe' must be blocked (final ext is exe)."""
        file_info, error = self._upload('report.pdf.exe')
        self.assertIsNone(file_info)
        self.assertIsNotNone(error)

    def test_null_file_returns_error(self):
        """Passing None as the file object must return an error gracefully."""
        from utils.file_handler import save_uploaded_file
        file_info, error = save_uploaded_file(None)
        self.assertIsNone(file_info)
        self.assertIsNotNone(error)


if __name__ == '__main__':
    unittest.main()
