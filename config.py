"""
Configuración profesional para OSINT Framework CTI
Soporta: desarrollo local, PythonAnywhere, y despliegue en cloud
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).parent


class Config:
    """Configuración base"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-cambiar-en-produccion'

    # Base de datos
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f'sqlite:///{BASE_DIR}/osint_framework.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True
    }

    # JWT
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-cambiar'
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hora

    # Rate Limiting
    RATELIMIT_STORAGE_URI = os.environ.get('REDIS_URL') or 'memory://'
    RATELIMIT_STRATEGY = 'fixed-window'
    RATELIMIT_DEFAULT = "100 per minute"

    # APIs Externas
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    HYBRID_ANALYSIS_API_KEY = os.environ.get('HYBRID_ANALYSIS_API_KEY', '')
    ALIENVAULT_OTX_API_KEY = os.environ.get('ALIENVAULT_OTX_API_KEY', '')
    CENSYS_API_ID = os.environ.get('CENSYS_API_ID', '')
    CENSYS_API_SECRET = os.environ.get('CENSYS_API_SECRET', '')
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')

    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

    @classmethod
    def is_production(cls):
        return os.environ.get('FLASK_ENV') == 'production'


class DevelopmentConfig(Config):
    """Configuración desarrollo"""
    DEBUG = True
    SQLALCHEMY_ECHO = True


class ProductionConfig(Config):
    """Configuración producción"""
    DEBUG = False
    SQLALCHEMY_ECHO = False


# Diccionario de configuraciones
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}