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
                elif key == 'MAXMIND_LICENSE_KEY':
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
            'MAXMIND_LICENSE_KEY': os.getenv('MAXMIND_LICENSE_KEY', ''),
            'VIRUSTOTAL_NO_SSL_CHECK': os.getenv('VIRUSTOTAL_NO_SSL_CHECK', 'False').lower() == 'true',
            'URLSCAN_NO_SSL_CHECK': os.getenv('URLSCAN_NO_SSL_CHECK', 'False').lower() == 'true',
            'URL_ENRICHMENT_NO_SSL_CHECK': os.getenv('URL_ENRICHMENT_NO_SSL_CHECK', 'False').lower() == 'true',
            'DOMAIN_ENRICHMENT_NO_SSL_CHECK': os.getenv('DOMAIN_ENRICHMENT_NO_SSL_CHECK', 'False').lower() == 'true',
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

        flash('Configuration reloaded successfully! API keys are now active.', 'success')
    except Exception as e:
        flash(f'Error reloading configuration: {str(e)}', 'danger')

    return redirect(url_for('admin.api_keys'))
