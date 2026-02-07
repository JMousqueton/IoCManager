"""Comment routes - Manage comments on IOCs"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.ioc import IOC
from app.models.comment import Comment
from app.models.audit import AuditLog
from datetime import datetime

comment_bp = Blueprint('comment', __name__, url_prefix='/comments')


@comment_bp.route('/create', methods=['POST'])
@login_required
def create():
    """Create a new comment on an IOC"""
    ioc_id = request.form.get('ioc_id', type=int)
    parent_id = request.form.get('parent_id', type=int)  # Optional, for replies
    content = request.form.get('content', '').strip()

    if not ioc_id:
        flash('IOC ID is required.', 'danger')
        return redirect(request.referrer or url_for('main.index'))

    if not content:
        flash('Comment content cannot be empty.', 'danger')
        return redirect(url_for('ioc.detail', id=ioc_id))

    # Validate IOC exists
    ioc = IOC.query.get_or_404(ioc_id)

    # Validate parent comment if replying
    if parent_id:
        parent_comment = Comment.query.get_or_404(parent_id)
        # Ensure parent comment belongs to the same IOC
        if parent_comment.ioc_id != ioc_id:
            flash('Invalid parent comment.', 'danger')
            return redirect(url_for('ioc.detail', id=ioc_id))

    # Create comment
    comment = Comment(
        ioc_id=ioc_id,
        user_id=current_user.id,
        parent_id=parent_id,
        content=content
    )

    try:
        db.session.add(comment)
        db.session.commit()

        # Audit log
        comment_type = 'reply' if parent_id else 'comment'
        log = AuditLog(
            user_id=current_user.id,
            action='CREATE',
            resource_type='Comment',
            resource_id=comment.id,
            details=f'Created {comment_type} on IOC#{ioc_id}'
        )
        db.session.add(log)
        db.session.commit()

        # TODO: Send notifications to mentioned users
        mentioned_users = comment.get_mentioned_users()
        if mentioned_users:
            # Future: implement notification system
            pass

        flash('Comment posted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating comment: {str(e)}', 'danger')

    return redirect(url_for('ioc.detail', id=ioc_id) + '#comments')


@comment_bp.route('/<int:id>/edit', methods=['POST'])
@login_required
def edit(id):
    """Edit an existing comment"""
    comment = Comment.query.get_or_404(id)

    # Check permission
    if not comment.can_edit(current_user):
        flash('You do not have permission to edit this comment.', 'danger')
        return redirect(url_for('ioc.detail', id=comment.ioc_id))

    content = request.form.get('content', '').strip()

    if not content:
        flash('Comment content cannot be empty.', 'danger')
        return redirect(url_for('ioc.detail', id=comment.ioc_id))

    old_content = comment.content

    try:
        comment.content = content
        comment.updated_at = datetime.utcnow()
        db.session.commit()

        # Audit log
        log = AuditLog(
            user_id=current_user.id,
            action='UPDATE',
            resource_type='Comment',
            resource_id=comment.id,
            details=f'Edited comment on IOC#{comment.ioc_id}'
        )
        db.session.add(log)
        db.session.commit()

        flash('Comment updated successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating comment: {str(e)}', 'danger')

    return redirect(url_for('ioc.detail', id=comment.ioc_id) + '#comments')


@comment_bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    """Delete a comment"""
    comment = Comment.query.get_or_404(id)
    ioc_id = comment.ioc_id

    # Check permission
    if not comment.can_delete(current_user):
        flash('You do not have permission to delete this comment.', 'danger')
        return redirect(url_for('ioc.detail', id=ioc_id))

    try:
        # Audit log before deletion
        log = AuditLog(
            user_id=current_user.id,
            action='DELETE',
            resource_type='Comment',
            resource_id=comment.id,
            details=f'Deleted comment on IOC#{ioc_id}'
        )
        db.session.add(log)

        # Delete comment (cascade will delete replies)
        db.session.delete(comment)
        db.session.commit()

        flash('Comment deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting comment: {str(e)}', 'danger')

    return redirect(url_for('ioc.detail', id=ioc_id) + '#comments')


@comment_bp.route('/search-users')
@login_required
def search_users():
    """Search users for @mentions (AJAX endpoint)"""
    from app.models.user import User

    query = request.args.get('q', '').strip()
    limit = request.args.get('limit', 10, type=int)

    if not query or len(query) < 2:
        return jsonify([])

    # Search users by username or email
    users = User.query.filter(
        db.or_(
            User.username.ilike(f'%{query}%'),
            User.email.ilike(f'%{query}%')
        )
    ).filter(User.is_active == True).limit(limit).all()

    return jsonify([{
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role
    } for user in users])
