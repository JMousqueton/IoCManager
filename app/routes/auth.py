"""Authentication routes blueprint"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user
from app import db
from app.models.user import User
from app.forms.auth import LoginForm, RegistrationForm
from urllib.parse import urlparse

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""

    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('auth.login'))

        if not user.is_active:
            flash('Your account has been deactivated. Please contact an administrator.', 'warning')
            return redirect(url_for('auth.login'))

        # Check if MFA is enabled
        if user.mfa_enabled:
            # Store user ID in session temporarily (not logged in yet!)
            from flask import session
            from datetime import datetime
            session['mfa_user_id'] = user.id
            session['mfa_remember'] = form.remember_me.data
            session['mfa_timestamp'] = datetime.utcnow().isoformat()
            return redirect(url_for('auth.mfa_verify'))

        # Original login flow for non-MFA users
        login_user(user, remember=form.remember_me.data)
        user.update_last_login()

        flash(f'Welcome back, {user.username}!', 'success')

        # Redirect to the page the user was trying to access
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('main.index')

        return redirect(next_page)

    return render_template('auth/login.html', form=form)


@auth_bp.route('/logout')
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""

    # Check if registration is enabled
    from flask import current_app
    if not current_app.config.get('REGISTRATION_ENABLED', False):
        flash('Registration is currently disabled. Please contact an administrator.', 'warning')
        return redirect(url_for('auth.login'))

    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = RegistrationForm()

    if form.validate_on_submit():
        # Create new user with default 'Viewer' role
        user = User(
            username=form.username.data,
            email=form.email.data,
            role='Viewer'  # Default role for self-registered users
        )
        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form)


@auth_bp.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    """MFA verification after password authentication"""
    from datetime import datetime, timedelta
    from flask import session
    from app.models.audit import MFAVerificationAttempt
    from app.forms.user import MFAVerifyForm

    # Check if user came from login
    if 'mfa_user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('auth.login'))

    # Check session timeout (5 minutes)
    if 'mfa_timestamp' in session:
        timestamp = datetime.fromisoformat(session['mfa_timestamp'])
        if datetime.utcnow() - timestamp > timedelta(minutes=5):
            session.clear()
            flash('MFA verification timed out. Please log in again.', 'warning')
            return redirect(url_for('auth.login'))

    user = User.query.get(session['mfa_user_id'])
    if not user or not user.mfa_enabled:
        session.clear()
        return redirect(url_for('auth.login'))

    form = MFAVerifyForm()

    if form.validate_on_submit():
        # Rate limiting check
        recent_attempts = MFAVerificationAttempt.query.filter(
            MFAVerificationAttempt.user_id == user.id,
            MFAVerificationAttempt.timestamp > datetime.utcnow() - timedelta(minutes=15)
        ).count()

        if recent_attempts >= 10:
            flash('Too many failed attempts. Please try again later.', 'danger')
            return render_template('auth/mfa_verify.html', form=form)

        verified = False
        attempt_type = 'totp'

        if form.use_backup_code.data:
            verified = user.verify_backup_code(form.code.data)
            attempt_type = 'backup'
        else:
            verified = user.verify_totp(form.code.data)

        # Log attempt
        attempt = MFAVerificationAttempt(
            user_id=user.id,
            ip_address=request.remote_addr,
            success=verified,
            attempt_type=attempt_type
        )
        db.session.add(attempt)
        db.session.commit()

        if verified:
            # Successful verification - complete login
            login_user(user, remember=session.get('mfa_remember', False))
            user.update_last_login()
            user.mfa_last_used = datetime.utcnow()
            db.session.commit()

            # Audit log
            from app.models.audit import AuditLog
            log = AuditLog(
                user_id=user.id,
                action='LOGIN',
                resource_type='User',
                resource_id=user.id,
                details='Successful MFA login'
            )
            db.session.add(log)
            db.session.commit()

            # Clean up session
            session.pop('mfa_user_id', None)
            session.pop('mfa_remember', None)
            session.pop('mfa_timestamp', None)

            flash(f'Welcome back, {user.username}!', 'success')

            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('main.index')

            return redirect(next_page)
        else:
            flash('Invalid authentication code. Please try again.', 'danger')

    return render_template('auth/mfa_verify.html', form=form)
