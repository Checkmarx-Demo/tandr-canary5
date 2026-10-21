# Configuration file
# All secrets and credentials are loaded from environment variables.
# Do NOT hardcode credentials here. Set the corresponding environment
# variables before starting the application.

import os

class Config:
    # JWT secret must be set via environment variable
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or os.environ.get('JWT_SECRET')

    DATABASE_URL = os.environ.get('DATABASE_URL')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # AWS credentials must be supplied via environment variables (or IAM role)
    AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
    AWS_S3_BUCKET = os.environ.get('AWS_S3_BUCKET', 'projecthub-files-public')

    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@projecthub.com')
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

