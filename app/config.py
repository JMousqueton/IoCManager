import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get the base directory of the project
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

class Config:
    """Base configuration class"""

    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', f'sqlite:///{os.path.join(basedir, "instance", "ioc_manager.db")}')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 300,
        'pool_pre_ping': True,
    }

    # VirusTotal
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    VIRUSTOTAL_API_URL = os.getenv('VIRUSTOTAL_API_URL', 'https://www.virustotal.com/vtapi/v2')
    VIRUSTOTAL_RATE_LIMIT = int(os.getenv('VIRUSTOTAL_RATE_LIMIT', 4))
    VIRUSTOTAL_CACHE_DAYS = int(os.getenv('VIRUSTOTAL_CACHE_DAYS', 7))
    VIRUSTOTAL_NO_SSL_CHECK = os.getenv('VIRUSTOTAL_NO_SSL_CHECK', 'False').lower() == 'true'

    # URLScan.io
    URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY', '')
    URLSCAN_RATE_LIMIT = int(os.getenv('URLSCAN_RATE_LIMIT', 1))
    URLSCAN_CACHE_DAYS = int(os.getenv('URLSCAN_CACHE_DAYS', 7))
    URLSCAN_NO_SSL_CHECK = os.getenv('URLSCAN_NO_SSL_CHECK', 'False').lower() == 'true'

    # AS Lookup
    ASN_DATABASE_PATH = os.getenv('ASN_DATABASE_PATH', os.path.join(basedir, 'data', 'ipasn.dat'))
    ASN_CACHE_DAYS = int(os.getenv('ASN_CACHE_DAYS', 30))

    # Domain Enrichment
    DOMAIN_ENRICHMENT_CACHE_DAYS = int(os.getenv('DOMAIN_ENRICHMENT_CACHE_DAYS', 30))
    DOMAIN_ENRICHMENT_NO_SSL_CHECK = os.getenv('DOMAIN_ENRICHMENT_NO_SSL_CHECK', 'False').lower() == 'true'

    # URL Enrichment
    URL_ENRICHMENT_CACHE_DAYS = int(os.getenv('URL_ENRICHMENT_CACHE_DAYS', 7))
    URL_ENRICHMENT_NO_SSL_CHECK = os.getenv('URL_ENRICHMENT_NO_SSL_CHECK', 'False').lower() == 'true'

    # Email
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'localhost')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
    MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'ioc-manager@example.com')

    # Email Reports
    DAILY_REPORT_RECIPIENTS = os.getenv('DAILY_REPORT_RECIPIENTS', '').split(',')
    WEEKLY_REPORT_RECIPIENTS = os.getenv('WEEKLY_REPORT_RECIPIENTS', '').split(',')
    REPORT_ENABLED = os.getenv('REPORT_ENABLED', 'True').lower() == 'true'

    # Session
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(seconds=int(os.getenv('PERMANENT_SESSION_LIFETIME', 28800)))

    # Authentication
    REGISTRATION_ENABLED = os.getenv('REGISTRATION_ENABLED', 'False').lower() == 'true'

    # Application
    ITEMS_PER_PAGE = int(os.getenv('ITEMS_PER_PAGE', 50))
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))

    # IOC Expiration
    IOC_DEFAULT_TTL_DAYS = int(os.getenv('IOC_DEFAULT_TTL_DAYS', 0))  # 0 = no expiration
    IOC_AUTO_EXPIRE_ENABLED = os.getenv('IOC_AUTO_EXPIRE_ENABLED', 'False').lower() == 'true'

    # MFA Configuration
    MFA_ENABLED = os.getenv('MFA_ENABLED', 'True').lower() == 'true'
    MFA_ISSUER_NAME = os.getenv('MFA_ISSUER_NAME', 'IOC Manager')
    MFA_RATE_LIMIT_ATTEMPTS = int(os.getenv('MFA_RATE_LIMIT_ATTEMPTS', '10'))
    MFA_RATE_LIMIT_WINDOW = int(os.getenv('MFA_RATE_LIMIT_WINDOW', '15'))  # minutes

    # WTForms
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
