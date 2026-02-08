"""User management routes blueprint"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.audit import AuditLog
from app.forms.user import UserForm, ProfileForm, ChangePasswordForm

user_bp = Blueprint('user', __name__)


@user_bp.route('/')
@login_required
def list():
    """List all users (admin only)"""

    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.index'))

    page = request.args.get('page', 1, type=int)
    per_page = 25

    pagination = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    users = pagination.items

    return render_template('user/list.html', users=users, pagination=pagination)


@user_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """Create new user (admin only)"""

    if not current_user.is_admin():
        flash('You do not have permission to create users.', 'danger')
        return redirect(url_for('main.index'))

    form = UserForm()

    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            role=form.role.data,
            is_active=form.is_active.data,
            created_by=current_user.id
        )

        # Set password if provided
        if form.password.data:
            user.set_password(form.password.data)
        else:
            # Set a default password that must be changed
            user.set_password('ChangeMe123!')

        db.session.add(user)
        db.session.flush()  # Flush to get user.id

        # Audit log
        log = AuditLog(
            user_id=current_user.id,
            action='CREATE',
            resource_type='User',
            resource_id=user.id,
            details=f'Created user {user.username} with role {user.role}'
        )
        db.session.add(log)
        db.session.commit()

        flash(f'User {user.username} created successfully.', 'success')
        return redirect(url_for('user.detail', id=user.id))

    return render_template('user/create.html', form=form)


@user_bp.route('/<int:id>')
@login_required
def detail(id):
    """View user details"""

    user = User.query.get_or_404(id)

    # Non-admins can only view their own profile
    if not current_user.is_admin() and current_user.id != user.id:
        flash('You do not have permission to view this user profile.', 'danger')
        return redirect(url_for('main.index'))

    return render_template('user/detail.html', user=user)


@user_bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    """Edit user (admin only)"""

    if not current_user.is_admin():
        flash('You do not have permission to edit users.', 'danger')
        return redirect(url_for('main.index'))

    user = User.query.get_or_404(id)

    form = UserForm(
        original_username=user.username,
        original_email=user.email
    )

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.role = form.role.data
        user.is_active = form.is_active.data

        # Update password if provided
        if form.password.data:
            user.set_password(form.password.data)

        # Audit log
        log = AuditLog(
            user_id=current_user.id,
            action='UPDATE',
            resource_type='User',
            resource_id=user.id,
            details=f'Updated user {user.username} (role: {user.role}, active: {user.is_active})'
        )
        db.session.add(log)
        db.session.commit()

        flash('User updated successfully.', 'success')
        return redirect(url_for('user.detail', id=id))

    # Populate form with existing data
    form.username.data = user.username
    form.email.data = user.email
    form.role.data = user.role
    form.is_active.data = user.is_active

    return render_template('user/edit.html', form=form, user=user)


@user_bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    """Delete user (admin only)"""

    if not current_user.is_admin():
        flash('You do not have permission to delete users.', 'danger')
        return redirect(url_for('main.index'))

    user = User.query.get_or_404(id)

    # Prevent deleting yourself
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('user.list'))

    username = user.username
    user_id = user.id

    # Audit log (before deletion)
    log = AuditLog(
        user_id=current_user.id,
        action='DELETE',
        resource_type='User',
        resource_id=user_id,
        details=f'Deleted user {username}'
    )
    db.session.add(log)

    db.session.delete(user)
    db.session.commit()

    flash(f'User {username} deleted successfully.', 'success')
    return redirect(url_for('user.list'))


@user_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """Edit own profile"""

    form = ProfileForm()

    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()

        flash('Profile updated successfully.', 'success')
        return redirect(url_for('user.profile'))

    # Populate form with current user data
    form.username.data = current_user.username
    form.email.data = current_user.email

    return render_template('user/profile.html', form=form)


@user_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change own password"""

    form = ChangePasswordForm()

    if form.validate_on_submit():
        current_user.set_password(form.new_password.data)
        db.session.commit()

        flash('Password changed successfully.', 'success')
        return redirect(url_for('user.profile'))

    return render_template('user/change_password.html', form=form)
