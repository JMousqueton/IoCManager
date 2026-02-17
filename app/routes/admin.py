"""Admin routes - System administration"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, current_app
from flask_login import login_required, current_user
from functools import wraps
from pathlib import Path
import os
from dotenv import load_dotenv
from app import db
from app.models.tag import Tag
from app.models.audit import AuditLog
from app.models.user import User
from app.forms.admin import AuditLogSearchForm
from datetime import datetime, timedelta

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))

        if not current_user.is_admin():
            flash('You do not have permission to access this page.', 'danger')
            abort(403)

        return f(*args, **kwargs)
    return decorated_function


def reviewer_required(f):
    """Decorator to require reviewer flag or admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))

        if not current_user.can_review_ioc():
            flash('You do not have permission to access this page.', 'danger')
            abort(403)

        return f(*args, **kwargs)
    return decorated_function


@admin_bp.route('/')
@login_required
@admin_required
def index():
    """Admin dashboard - defaults to tags management"""
    return redirect(url_for('admin.tags'))


@admin_bp.route('/tags')
@login_required
@admin_required
def tags():
    """Tag management page"""
    from app.models.ioc import IOC

    # Get all tags
    all_tags = Tag.query.order_by(Tag.name).all()

    # Get IOC counts for each tag
    tags_with_counts = []
    for tag in all_tags:
        # Count IOCs that have this tag
        ioc_count = db.session.query(IOC).join(IOC.tags).filter(Tag.id == tag.id).count()

        tag_dict = {
            'id': tag.id,
            'name': tag.name,
            'description': tag.description,
            'color': tag.color,
            'ioc_count': ioc_count
        }
        tags_with_counts.append((tag, tag_dict))

    return render_template('admin/index.html',
                         active_tab='tags',
                         tags=tags_with_counts)


@admin_bp.route('/tags/create', methods=['POST'])
@login_required
@admin_required
def create_tag():
    """Create a new tag"""
    name = request.form.get('name', '').strip().lower()
    description = request.form.get('description', '').strip()
    color = request.form.get('color', '#6c757d').strip()

    if not name:
        flash('Tag name is required.', 'danger')
        return redirect(url_for('admin.tags'))

    # Check if tag already exists
    existing_tag = Tag.query.filter_by(name=name).first()
    if existing_tag:
        flash(f'Tag "{name}" already exists.', 'warning')
        return redirect(url_for('admin.tags'))

    # Create new tag
    new_tag = Tag(
        name=name,
        description=description,
        color=color
    )

    try:
        db.session.add(new_tag)
        db.session.commit()

        # Audit log
        log = AuditLog(
            user_id=current_user.id,
            action='CREATE',
            resource_type='Tag',
            resource_id=new_tag.id,
            details=f'Created tag: {name}'
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Tag "{name}" created successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating tag: {str(e)}', 'danger')

    return redirect(url_for('admin.tags'))


@admin_bp.route('/tags/<int:id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_tag(id):
    """Edit an existing tag"""
    tag = Tag.query.get_or_404(id)

    old_name = tag.name
    name = request.form.get('name', '').strip().lower()
    description = request.form.get('description', '').strip()
    color = request.form.get('color', '#6c757d').strip()

    if not name:
        flash('Tag name is required.', 'danger')
        return redirect(url_for('admin.tags'))

    # Check if new name conflicts with another tag
    if name != old_name:
        existing_tag = Tag.query.filter_by(name=name).first()
        if existing_tag:
            flash(f'Tag name "{name}" is already in use.', 'warning')
            return redirect(url_for('admin.tags'))

    # Update tag
    tag.name = name
    tag.description = description
    tag.color = color

    try:
        db.session.commit()

        # Audit log
        log = AuditLog(
            user_id=current_user.id,
            action='UPDATE',
            resource_type='Tag',
            resource_id=tag.id,
            details=f'Updated tag: {old_name} -> {name}'
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Tag "{name}" updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating tag: {str(e)}', 'danger')

    return redirect(url_for('admin.tags'))


@admin_bp.route('/tags/<int:id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_tag(id):
    """Delete a tag and remove it from all IOCs"""
    from app.models.ioc import IOC

    tag = Tag.query.get_or_404(id)
    tag_name = tag.name

    # Find all IOCs that have this tag
    iocs_with_tag = db.session.query(IOC).join(IOC.tags).filter(Tag.id == tag.id).all()
    ioc_count = len(iocs_with_tag)

    try:
        # Remove tag from all IOCs
        for ioc in iocs_with_tag:
            ioc.tags.remove(tag)

        # Audit log before deletion
        details = f'Deleted tag: {tag_name}'
        if ioc_count > 0:
            details += f' (removed from {ioc_count} IOC(s))'

        log = AuditLog(
            user_id=current_user.id,
            action='DELETE',
            resource_type='Tag',
            resource_id=tag.id,
            details=details
        )
        db.session.add(log)

        # Delete tag
        db.session.delete(tag)
        db.session.commit()

        if ioc_count > 0:
            flash(f'Tag "{tag_name}" deleted successfully and removed from {ioc_count} IOC(s).', 'success')
        else:
            flash(f'Tag "{tag_name}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting tag: {str(e)}', 'danger')

    return redirect(url_for('admin.tags'))


@admin_bp.route('/operating-systems')
@login_required
@admin_required
def operating_systems():
    """Operating Systems management page"""
    from app.models.operating_system import OperatingSystem

    operating_systems_list = OperatingSystem.query.order_by(OperatingSystem.name).all()

    return render_template('admin/index.html',
                          active_tab='operating_systems',
                          operating_systems=operating_systems_list)


@admin_bp.route('/operating-systems/create', methods=['POST'])
@login_required
@admin_required
def create_operating_system():
    """Create a new operating system"""
    from app.models.operating_system import OperatingSystem

    name = request.form.get('name', '').strip()
    icon = request.form.get('icon', '').strip()
    description = request.form.get('description', '').strip()

    if not name:
        flash('Operating system name is required.', 'danger')
        return redirect(url_for('admin.operating_systems'))

    # Check if OS already exists
    existing = OperatingSystem.query.filter_by(name=name).first()
    if existing:
        flash(f'Operating system "{name}" already exists.', 'warning')
        return redirect(url_for('admin.operating_systems'))

    try:
        new_os = OperatingSystem(name=name, icon=icon, description=description)
        db.session.add(new_os)
        db.session.commit()
        flash(f'Operating system "{name}" created successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating operating system: {str(e)}', 'danger')

    return redirect(url_for('admin.operating_systems'))


@admin_bp.route('/operating-systems/<int:id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_operating_system(id):
    """Edit an existing operating system"""
    from app.models.operating_system import OperatingSystem

    os_entry = OperatingSystem.query.get_or_404(id)

    name = request.form.get('name', '').strip()
    icon = request.form.get('icon', '').strip()
    description = request.form.get('description', '').strip()

    if not name:
        flash('Operating system name is required.', 'danger')
        return redirect(url_for('admin.operating_systems'))

    # Check if name is already used by another OS
    existing = OperatingSystem.query.filter(
        OperatingSystem.name == name,
        OperatingSystem.id != id
    ).first()

    if existing:
        flash(f'Operating system "{name}" already exists.', 'warning')
        return redirect(url_for('admin.operating_systems'))

    try:
        os_entry.name = name
        os_entry.icon = icon
        os_entry.description = description
        db.session.commit()
        flash(f'Operating system "{name}" updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating operating system: {str(e)}', 'danger')

    return redirect(url_for('admin.operating_systems'))


@admin_bp.route('/operating-systems/<int:id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_operating_system(id):
    """Delete an operating system"""
    from app.models.operating_system import OperatingSystem

    os_entry = OperatingSystem.query.get_or_404(id)
    os_name = os_entry.name

    try:
        # Check how many IOCs use this OS
        ioc_count = os_entry.iocs.count()

        # Delete the OS (will set operating_system_id to NULL in IOCs)
        db.session.delete(os_entry)
        db.session.commit()

        if ioc_count > 0:
            flash(f'Operating system "{os_name}" deleted successfully. {ioc_count} IOC(s) were using this OS.', 'success')
        else:
            flash(f'Operating system "{os_name}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting operating system: {str(e)}', 'danger')

    return redirect(url_for('admin.operating_systems'))


@admin_bp.route('/api-keys')
@login_required
@admin_required
def api_keys():
    """API Keys management page"""
    # Read current API keys from .env file
    env_path = Path('.env')
    api_keys = {
        'VIRUSTOTAL_API_KEY': '',
        'URLSCAN_API_KEY': '',
        'MAXMIND_ACCOUNT_ID': '',
        'MAXMIND_LICENSE_KEY': ''
    }

    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                for key in api_keys.keys():
                    if line.startswith(f'{key}='):
                        # Extract value after = (handle both quoted and unquoted values)
                        value = line.split('=', 1)[1].strip()
                        # Remove quotes if present
                        value = value.strip('"\'')
                        api_keys[key] = value
                        break

    return render_template('admin/index.html',
                         active_tab='api-keys',
                         api_keys=api_keys)


@admin_bp.route('/api-keys/save', methods=['POST'])
@login_required
@admin_required
def save_api_keys():
    """Save API keys to .env file"""
    virustotal_key = request.form.get('virustotal_key', '').strip()
    urlscan_key = request.form.get('urlscan_key', '').strip()
    maxmind_account_id = request.form.get('maxmind_account_id', '').strip()
    maxmind_key = request.form.get('maxmind_key', '').strip()

    env_path = Path('.env')

    try:
        # Read current .env file
        env_lines = []
        if env_path.exists():
            with open(env_path, 'r') as f:
                env_lines = f.readlines()

        # Update API keys in the lines
        keys_to_update = {
            'VIRUSTOTAL_API_KEY': virustotal_key,
            'URLSCAN_API_KEY': urlscan_key,
            'MAXMIND_ACCOUNT_ID': maxmind_account_id,
            'MAXMIND_LICENSE_KEY': maxmind_key
        }

        updated_keys = set()
        new_lines = []

        for line in env_lines:
            line_stripped = line.strip()
            updated = False

            for key, value in keys_to_update.items():
                if line_stripped.startswith(f'{key}='):
                    # Update existing key
                    new_lines.append(f'{key}={value}\n')
                    updated_keys.add(key)
                    updated = True
                    break

            if not updated:
                new_lines.append(line)

        # Add any keys that weren't found in the file
        for key, value in keys_to_update.items():
            if key not in updated_keys:
                # Find the appropriate section to add the key
                insert_index = len(new_lines)

                if key == 'VIRUSTOTAL_API_KEY':
                    # Find VirusTotal section
                    for i, line in enumerate(new_lines):
                        if 'VirusTotal' in line or 'VIRUSTOTAL' in line:
                            insert_index = i + 1
                            break
                elif key == 'URLSCAN_API_KEY':
                    # Find URLScan section
                    for i, line in enumerate(new_lines):
                        if 'URLScan' in line or 'URLSCAN' in line:
                            insert_index = i + 1
                            break
                elif key in ('MAXMIND_ACCOUNT_ID', 'MAXMIND_LICENSE_KEY'):
                    # Find MaxMind section
                    for i, line in enumerate(new_lines):
                        if 'MaxMind' in line or 'MAXMIND' in line:
                            insert_index = i + 1
                            break

                new_lines.insert(insert_index, f'{key}={value}\n')

        # Write updated content back to .env
        with open(env_path, 'w') as f:
            f.writelines(new_lines)

        # Audit log
        log = AuditLog(
            user_id=current_user.id,
            action='UPDATE',
            resource_type='Configuration',
            resource_id=None,
            details='Updated API keys configuration'
        )
        db.session.add(log)
        db.session.commit()

        flash('API keys saved successfully. Click "Reload Configuration" to apply changes without restart.', 'success')
    except Exception as e:
        flash(f'Error saving API keys: {str(e)}', 'danger')

    return redirect(url_for('admin.api_keys'))


@admin_bp.route('/api-keys/reload', methods=['POST'])
@login_required
@admin_required
def reload_config():
    """Reload configuration from .env file without restarting the application"""
    try:
        # Reload .env file
        load_dotenv(override=True)

        # Update Flask config with new environment variables
        config_keys_to_update = {
            'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'URLSCAN_API_KEY': os.getenv('URLSCAN_API_KEY', ''),
            'MAXMIND_ACCOUNT_ID': os.getenv('MAXMIND_ACCOUNT_ID', ''),
            'MAXMIND_LICENSE_KEY': os.getenv('MAXMIND_LICENSE_KEY', ''),
            'VIRUSTOTAL_NO_SSL_CHECK': os.getenv('VIRUSTOTAL_NO_SSL_CHECK', 'False').lower() == 'true',
            'URLSCAN_NO_SSL_CHECK': os.getenv('URLSCAN_NO_SSL_CHECK', 'False').lower() == 'true',
            'URL_ENRICHMENT_NO_SSL_CHECK': os.getenv('URL_ENRICHMENT_NO_SSL_CHECK', 'False').lower() == 'true',
            'DOMAIN_ENRICHMENT_NO_SSL_CHECK': os.getenv('DOMAIN_ENRICHMENT_NO_SSL_CHECK', 'False').lower() == 'true',
            # Mail configuration
            'MAIL_SERVER': os.getenv('MAIL_SERVER', 'localhost'),
            'MAIL_PORT': int(os.getenv('MAIL_PORT', 587)),
            'MAIL_USE_TLS': os.getenv('MAIL_USE_TLS', 'True').lower() == 'true',
            'MAIL_USE_SSL': os.getenv('MAIL_USE_SSL', 'False').lower() == 'true',
            'MAIL_USERNAME': os.getenv('MAIL_USERNAME', ''),
            'MAIL_PASSWORD': os.getenv('MAIL_PASSWORD', ''),
            'MAIL_DEFAULT_SENDER': os.getenv('MAIL_DEFAULT_SENDER', 'ioc-manager@example.com'),
            # Report configuration
            'DAILY_REPORT_RECIPIENTS': os.getenv('DAILY_REPORT_RECIPIENTS', '').split(','),
            'WEEKLY_REPORT_RECIPIENTS': os.getenv('WEEKLY_REPORT_RECIPIENTS', '').split(','),
            'REPORT_ENABLED': os.getenv('REPORT_ENABLED', 'True').lower() == 'true',
        }

        # Update current app config
        for key, value in config_keys_to_update.items():
            current_app.config[key] = value

        # Audit log
        log = AuditLog(
            user_id=current_user.id,
            action='UPDATE',
            resource_type='Configuration',
            resource_id=None,
            details='Reloaded configuration from .env file'
        )
        db.session.add(log)
        db.session.commit()

        flash('Configuration reloaded successfully! Changes are now active.', 'success')
    except Exception as e:
        flash(f'Error reloading configuration: {str(e)}', 'danger')

    # Redirect back to the referring page or default to api_keys
    referer = request.referrer
    if referer and 'reports' in referer:
        return redirect(url_for('admin.reports'))
    else:
        return redirect(url_for('admin.api_keys'))


@admin_bp.route('/reports')
@login_required
@admin_required
def reports():
    """Report configuration management page"""
    # Read current report settings from .env file
    env_path = Path('.env')
    report_config = {
        'MAIL_SERVER': '',
        'MAIL_PORT': '',
        'MAIL_USE_TLS': '',
        'MAIL_USE_SSL': '',
        'MAIL_USERNAME': '',
        'MAIL_PASSWORD': '',
        'MAIL_DEFAULT_SENDER': '',
        'DAILY_REPORT_RECIPIENTS': '',
        'WEEKLY_REPORT_RECIPIENTS': '',
        'REPORT_ENABLED': ''
    }

    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                for key in report_config.keys():
                    if line.startswith(f'{key}='):
                        # Extract value after = (handle both quoted and unquoted values)
                        value = line.split('=', 1)[1].strip()
                        # Remove quotes if present
                        value = value.strip('"\'')
                        report_config[key] = value
                        break

    return render_template('admin/index.html',
                         active_tab='reports',
                         report_config=report_config)


@admin_bp.route('/reports/save', methods=['POST'])
@login_required
@admin_required
def save_reports():
    """Save report configuration to .env file"""
    mail_server = request.form.get('mail_server', '').strip()
    mail_port = request.form.get('mail_port', '').strip()
    mail_use_tls = request.form.get('mail_use_tls', '').strip()
    mail_use_ssl = request.form.get('mail_use_ssl', '').strip()
    mail_username = request.form.get('mail_username', '').strip()
    mail_password = request.form.get('mail_password', '').strip()
    mail_default_sender = request.form.get('mail_default_sender', '').strip()
    daily_recipients = request.form.get('daily_recipients', '').strip()
    weekly_recipients = request.form.get('weekly_recipients', '').strip()
    report_enabled = request.form.get('report_enabled', '').strip()

    env_path = Path('.env')

    try:
        # Read current .env file
        env_lines = []
        if env_path.exists():
            with open(env_path, 'r') as f:
                env_lines = f.readlines()

        # Update report config in the lines
        keys_to_update = {
            'MAIL_SERVER': mail_server,
            'MAIL_PORT': mail_port,
            'MAIL_USE_TLS': mail_use_tls,
            'MAIL_USE_SSL': mail_use_ssl,
            'MAIL_USERNAME': mail_username,
            'MAIL_PASSWORD': mail_password,
            'MAIL_DEFAULT_SENDER': mail_default_sender,
            'DAILY_REPORT_RECIPIENTS': daily_recipients,
            'WEEKLY_REPORT_RECIPIENTS': weekly_recipients,
            'REPORT_ENABLED': report_enabled
        }

        updated_keys = set()
        new_lines = []

        for line in env_lines:
            line_stripped = line.strip()
            updated = False

            for key, value in keys_to_update.items():
                if line_stripped.startswith(f'{key}='):
                    # Update existing key
                    new_lines.append(f'{key}={value}\n')
                    updated_keys.add(key)
                    updated = True
                    break

            if not updated:
                new_lines.append(line)

        # Add any keys that weren't found in the file
        for key, value in keys_to_update.items():
            if key not in updated_keys:
                # Find the appropriate section to add the key
                insert_index = len(new_lines)

                if key.startswith('MAIL_'):
                    # Find Email Configuration section
                    for i, line in enumerate(new_lines):
                        if 'Email Configuration' in line or 'MAIL_' in line:
                            insert_index = i + 1
                            break
                elif 'REPORT' in key:
                    # Find Email Reports section
                    for i, line in enumerate(new_lines):
                        if 'Email Reports' in line or 'REPORT_' in line:
                            insert_index = i + 1
                            break

                new_lines.insert(insert_index, f'{key}={value}\n')

        # Write updated content back to .env
        with open(env_path, 'w') as f:
            f.writelines(new_lines)

        # Audit log
        log = AuditLog(
            user_id=current_user.id,
            action='UPDATE',
            resource_type='Configuration',
            resource_id=None,
            details='Updated report configuration'
        )
        db.session.add(log)
        db.session.commit()

        flash('Report configuration saved successfully. Click "Reload Configuration" to apply changes without restart.', 'success')
    except Exception as e:
        flash(f'Error saving report configuration: {str(e)}', 'danger')

    return redirect(url_for('admin.reports'))


@admin_bp.route('/audit')
@login_required
@admin_required
def audit():
    """Audit logs page with search and filtering"""
    form = AuditLogSearchForm(request.args, meta={'csrf': False})

    # Populate user choices
    users = User.query.order_by(User.username).all()
    form.user_id.choices = [(0, 'All Users')] + [(u.id, u.username) for u in users]

    # Base query with relationship loading
    query = AuditLog.query.join(User, AuditLog.user_id == User.id)

    # Apply filters
    if form.resource_type.data:
        # When filtering by IOC, include IOC, IOCRelationship, and Comment
        if form.resource_type.data == 'IOC':
            query = query.filter(AuditLog.resource_type.in_(['IOC', 'IOCRelationship', 'Comment']))
        else:
            query = query.filter(AuditLog.resource_type == form.resource_type.data)

    if form.action.data:
        query = query.filter(AuditLog.action == form.action.data)

    if form.user_id.data and form.user_id.data != 0:
        query = query.filter(AuditLog.user_id == form.user_id.data)

    if form.date_from.data:
        # Start of day
        start_date = datetime.combine(form.date_from.data, datetime.min.time())
        query = query.filter(AuditLog.timestamp >= start_date)

    if form.date_to.data:
        # End of day
        end_date = datetime.combine(form.date_to.data, datetime.max.time())
        query = query.filter(AuditLog.timestamp <= end_date)

    # Pagination
    page = request.args.get('page', 1, type=int)
    per_page = 50
    pagination = query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    logs = pagination.items

    return render_template('admin/index.html',
                         active_tab='audit',
                         form=form,
                         logs=logs,
                         pagination=pagination)


@admin_bp.route('/audit/purge', methods=['POST'])
@login_required
@admin_required
def purge_audit_logs():
    """Purge audit logs older than 30 days"""
    try:
        # Calculate date 30 days ago
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)

        # Count logs to be deleted
        count = AuditLog.query.filter(AuditLog.timestamp < thirty_days_ago).count()

        # Delete old logs
        AuditLog.query.filter(AuditLog.timestamp < thirty_days_ago).delete()

        # Create audit log for this action
        log = AuditLog(
            user_id=current_user.id,
            action='DELETE',
            resource_type='AuditLog',
            resource_id=None,
            details=f'Purged {count} audit logs older than 30 days'
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Successfully purged {count} audit log(s) older than 30 days.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error purging audit logs: {str(e)}', 'danger')

    return redirect(url_for('admin.audit'))


# ──────────────────────────────────────────────────────────────
# Approvals Dashboard (accessible to Reviewers + Admins)
# ──────────────────────────────────────────────────────────────

@admin_bp.route('/approvals')
@login_required
@reviewer_required
def approvals():
    """IOC approval queue — shows all IOCs in 'review' status"""
    from app.models.ioc import IOC
    from app.services.notification_service import NotificationService

    pending_iocs = (
        IOC.query
        .filter(IOC.status == 'review')
        .order_by(IOC.updated_at.asc())
        .all()
    )

    pending_count = len(pending_iocs)

    return render_template(
        'admin/approvals.html',
        pending_iocs=pending_iocs,
        pending_count=pending_count,
    )


# ──────────────────────────────────────────────────────────────
# Reviewer Management (admin only)
# ──────────────────────────────────────────────────────────────

@admin_bp.route('/reviewers')
@login_required
@admin_required
def reviewers():
    """Manage reviewer flags on users"""
    all_users = User.query.filter(User.is_active == True).order_by(User.username).all()
    return render_template('admin/index.html', active_tab='reviewers', all_users=all_users)


@admin_bp.route('/reviewers/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_reviewer(user_id):
    """Toggle reviewer flag for a user"""
    user = User.query.get_or_404(user_id)
    user.is_reviewer = not user.is_reviewer
    action = 'granted' if user.is_reviewer else 'revoked'

    log = AuditLog(
        user_id=current_user.id,
        action='UPDATE',
        resource_type='User',
        resource_id=user.id,
        details=f'Reviewer role {action} for user: {user.username}'
    )
    db.session.add(log)
    db.session.commit()

    flash(f'Reviewer role {action} for {user.username}.', 'success')
    return redirect(url_for('admin.reviewers'))
