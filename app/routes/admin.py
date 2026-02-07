"""Admin routes - System administration"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from functools import wraps
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
