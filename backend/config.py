# Configuration file
# All secrets and credentials MUST be supplied via environment variables.
# Do NOT hardcode secrets, keys, or passwords in this file.

import os

class Config:
    # Secret key for JWT signing — required; no fallback default
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')

    DATABASE_URL = os.environ.get('DATABASE_URL')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # AWS credentials — loaded exclusively from environment variables
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_S3_BUCKET = os.environ.get('AWS_S3_BUCKET', 'projecthub-files-public')

    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@projecthub.com')
    # Admin password must be supplied via environment variable
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')

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

