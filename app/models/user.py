"""User model with RBAC"""

from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class User(UserMixin, db.Model):
    """User model for authentication and authorization"""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='Viewer')
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationships
    iocs_created = db.relationship('IOC', backref='creator', lazy='dynamic', foreign_keys='IOC.created_by')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    sessions = db.relationship('Session', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    # Check constraint for role
    __table_args__ = (
        db.CheckConstraint("role IN ('Viewer', 'User', 'Admin')", name='check_role'),
    )

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify password"""
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles):
        """Check if user has one of the specified roles"""
        return self.role in roles

    def is_admin(self):
        """Check if user is admin"""
        return self.role == 'Admin'

    def is_viewer(self):
        """Check if user is viewer (read-only)"""
        return self.role == 'Viewer'

    def can_modify_ioc(self, ioc):
        """Check if user can modify an IOC"""
        if self.is_admin():
            return True
        if self.role == 'User' and ioc.created_by == self.id:
            return True
        # Allow any user (including viewers) to edit IOCs marked for review
        if ioc.needs_review and self.role in ['User', 'Admin']:
            return True
        return False

    def can_delete_ioc(self, ioc):
        """Check if user can delete an IOC"""
        return self.can_modify_ioc(ioc)

    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        db.session.commit()

    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'
