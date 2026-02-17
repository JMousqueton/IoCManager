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

    # Reviewer flag (combinable with any role)
    is_reviewer = db.Column(db.Boolean, default=False, nullable=False, index=True)

    # MFA fields
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False, index=True)
    mfa_secret = db.Column(db.String(255), nullable=True)  # Encrypted TOTP secret
    mfa_backup_codes = db.Column(db.Text, nullable=True)  # JSON array of hashed codes
    mfa_backup_codes_used = db.Column(db.Text, nullable=True)  # JSON array of used indices
    mfa_enabled_at = db.Column(db.DateTime, nullable=True)
    mfa_last_used = db.Column(db.DateTime, nullable=True)

    # Relationships
    iocs_created = db.relationship('IOC', backref='creator', lazy='dynamic', foreign_keys='IOC.created_by')
    iocs_updated = db.relationship('IOC', backref='updater', lazy='dynamic', foreign_keys='IOC.updated_by')
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

    def can_review_ioc(self):
        """Check if user can review/approve/reject IOCs"""
        return self.is_admin() or self.is_reviewer

    def can_submit_for_review(self, ioc):
        """Check if user can submit an IOC for review"""
        if self.is_admin():
            return True
        return self.role == 'User' and ioc.created_by == self.id

    def can_archive_ioc(self, ioc):
        """Check if user can archive an IOC"""
        return self.is_admin() or self.is_reviewer

    def can_restore_ioc(self, ioc):
        """Check if user can restore an archived IOC"""
        return self.is_admin() or self.is_reviewer

    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        db.session.commit()

    # MFA Methods
    def set_mfa_secret(self, secret):
        """Encrypt and store MFA secret"""
        from app.utils.mfa import encrypt_secret
        self.mfa_secret = encrypt_secret(secret)

    def get_mfa_secret(self):
        """Decrypt MFA secret"""
        from app.utils.mfa import decrypt_secret
        if not self.mfa_secret:
            return None
        return decrypt_secret(self.mfa_secret)

    def verify_totp(self, code):
        """Verify TOTP code"""
        import pyotp
        if not self.mfa_enabled or not self.mfa_secret:
            return False
        totp = pyotp.TOTP(self.get_mfa_secret())
        return totp.verify(code, valid_window=1)  # Allow ±30 seconds for clock skew

    def generate_backup_codes(self, count=10):
        """Generate and store hashed backup codes"""
        import secrets
        import string
        import json
        from werkzeug.security import generate_password_hash
        codes = []
        for _ in range(count):
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            codes.append(f"{code[:4]}-{code[4:]}")  # Format: XXXX-XXXX
        hashed = [generate_password_hash(code) for code in codes]
        self.mfa_backup_codes = json.dumps(hashed)
        self.mfa_backup_codes_used = json.dumps([])
        return codes  # Return plaintext codes for one-time display

    def verify_backup_code(self, code):
        """Verify and mark backup code as used"""
        import json
        from werkzeug.security import check_password_hash
        if not self.mfa_backup_codes:
            return False
        codes = json.loads(self.mfa_backup_codes)
        used = json.loads(self.mfa_backup_codes_used or '[]')
        for idx, hashed_code in enumerate(codes):
            if idx not in used and check_password_hash(hashed_code, code):
                used.append(idx)
                self.mfa_backup_codes_used = json.dumps(used)
                db.session.commit()
                return True
        return False

    def get_remaining_backup_codes_count(self):
        """Count unused backup codes"""
        import json
        if not self.mfa_backup_codes:
            return 0
        codes = json.loads(self.mfa_backup_codes)
        used = json.loads(self.mfa_backup_codes_used or '[]')
        return len(codes) - len(used)

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
