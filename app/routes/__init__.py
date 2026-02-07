"""Routes package"""

from app.routes.main import main_bp
from app.routes.auth import auth_bp
from app.routes.ioc import ioc_bp
from app.routes.user import user_bp

__all__ = ['main_bp', 'auth_bp', 'ioc_bp', 'user_bp']
