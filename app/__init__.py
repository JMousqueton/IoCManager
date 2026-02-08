import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate
from flask_mail import Mail

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()
mail = Mail()


def create_app(config_name=None):
    """Application factory pattern"""

    app = Flask(__name__)

    # Load configuration
    if config_name is None:
        config_name = os.getenv('FLASK_ENV', 'development')

    from app.config import config
    app.config.from_object(config[config_name])

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)

    # Configure Flask-Login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    # User loader callback
    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        return User.query.get(int(user_id))

    # Register blueprints
    register_blueprints(app)

    # Register error handlers
    register_error_handlers(app)

    # Register template filters
    register_template_filters(app)

    # Create database tables
    with app.app_context():
        db.create_all()

    return app


def register_blueprints(app):
    """Register Flask blueprints"""

    # Import blueprints
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    from app.routes.ioc import ioc_bp
    from app.routes.user import user_bp
    from app.routes.ioc_export import export_bp
    from app.routes.tag_api import tag_api_bp
    from app.routes.admin import admin_bp
    from app.routes.ioc_relationship import relationship_bp
    from app.routes.comment import comment_bp

    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(ioc_bp, url_prefix='/iocs')
    app.register_blueprint(export_bp)
    app.register_blueprint(tag_api_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(user_bp, url_prefix='/users')
    app.register_blueprint(relationship_bp)
    app.register_blueprint(comment_bp)


def register_error_handlers(app):
    """Register error handlers"""

    from flask import render_template

    @app.errorhandler(403)
    def forbidden(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500


def register_template_filters(app):
    """Register custom Jinja2 filters"""

    from datetime import datetime

    @app.template_filter('datetime_format')
    def datetime_format(value, format='%Y-%m-%d %H:%M:%S'):
        """Format datetime object"""
        if value is None:
            return ''
        if isinstance(value, str):
            return value
        return value.strftime(format)

    @app.template_filter('severity_badge')
    def severity_badge(severity):
        """Return Bootstrap badge class for severity"""
        badges = {
            'Low': 'info',
            'Medium': 'warning',
            'High': 'danger',
            'Critical': 'dark'
        }
        return badges.get(severity, 'secondary')

    @app.template_filter('tlp_badge')
    def tlp_badge(tlp):
        """Return Bootstrap badge class for TLP"""
        badges = {
            'WHITE': 'light',
            'GREEN': 'success',
            'AMBER': 'warning',
            'RED': 'danger'
        }
        return badges.get(tlp, 'secondary')

    @app.template_filter('markdown')
    def markdown_filter(text):
        """Render markdown to HTML"""
        from app.utils.markdown import render_markdown
        from markupsafe import Markup
        return Markup(render_markdown(text))

    @app.template_filter('strip_markdown')
    def strip_markdown_filter(text, max_length=200):
        """Strip markdown formatting and return plain text"""
        from app.utils.markdown import strip_markdown
        return strip_markdown(text, max_length)

    @app.template_filter('txt_record_brand')
    def txt_record_brand_filter(txt_record):
        """Detect brand/service from TXT record"""
        from app.utils.txt_record_parser import get_txt_record_brand
        return get_txt_record_brand(txt_record)

    @app.template_filter('whois_status')
    def whois_status_filter(status):
        """Parse WHOIS status code to human-readable format"""
        from app.utils.whois_status_parser import parse_whois_status
        return parse_whois_status(status)

    @app.template_filter('extract_ioc_id')
    def extract_ioc_id_filter(text):
        """Extract IOC ID from text (e.g., 'IOC#123' or 'IOC #123' -> '123')"""
        import re
        if not text:
            return None
        # Match both "IOC#123" and "IOC #123" (with or without space/hash)
        match = re.search(r'IOC\s*#?(\d+)', text)
        return match.group(1) if match else None
