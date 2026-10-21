# Configuration file
# All sensitive values are loaded exclusively from environment variables.
# No default credentials are provided; the application will raise an error
# at startup if required environment variables are missing.

import os


def _require_env(name: str) -> str:
    """Return the value of an environment variable, raising if it is absent or empty."""
    value = os.environ.get(name)
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{name}' is not set. "
            "Set it before starting the application."
        )
    return value


class Config:
    JWT_SECRET_KEY = _require_env('JWT_SECRET_KEY')

    DATABASE_URL = _require_env('DATABASE_URL')
    SQLALCHEMY_DATABASE_URI = _require_env('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_S3_BUCKET = os.environ.get('AWS_S3_BUCKET', 'projecthub-files-public')

    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
    ADMIN_PASSWORD = _require_env('ADMIN_PASSWORD')

    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
    PERMANENT_SESSION_LIFETIME = None

    JWT_ALGORITHM = "HS256"
    JWT_EXPIRATION_DELTA = None

    UPLOAD_FOLDER = "/app/uploads"
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx', 'xml', 'php', 'exe', 'sh'}

    CORS_ORIGINS = "*"

    LOG_LEVEL = "DEBUG"
    LOG_FILE = "/app/logs/app.log"

    PASSWORD_HASH_ALGORITHM = "md5"

    API_RATE_LIMIT = None

