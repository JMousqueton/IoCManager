"""IOC Relationship routes - Manage relationships between IOCs"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.ioc import IOC
from app.models.ioc_relationship import IOCRelationship
from app.models.audit import AuditLog

relationship_bp = Blueprint('relationship', __name__, url_prefix='/relationships')


@relationship_bp.route('/create', methods=['POST'])
@login_required
def create():
    """Create a new relationship between IOCs"""
    source_ioc_id = request.form.get('source_ioc_id', type=int)
    target_ioc_id = request.form.get('target_ioc_id', type=int)
    relationship_type = request.form.get('relationship_type', '').strip()
    notes = request.form.get('notes', '').strip()

    if not source_ioc_id or not target_ioc_id:
        flash('Source and target IOCs are required.', 'danger')
        return redirect(request.referrer or url_for('main.index'))

    if not relationship_type:
        flash('Relationship type is required.', 'danger')
        return redirect(request.referrer or url_for('main.index'))

    # Validate IOCs exist
    source_ioc = IOC.query.get_or_404(source_ioc_id)
    target_ioc = IOC.query.get_or_404(target_ioc_id)

    # Prevent self-referencing
    if source_ioc_id == target_ioc_id:
        flash('Cannot create relationship to the same IOC.', 'warning')
        return redirect(url_for('ioc.detail', id=source_ioc_id))

    # Check if relationship already exists
    existing = IOCRelationship.query.filter_by(
        source_ioc_id=source_ioc_id,
        target_ioc_id=target_ioc_id,
        relationship_type=relationship_type
    ).first()

    if existing:
        flash('This relationship already exists.', 'warning')
        return redirect(url_for('ioc.detail', id=source_ioc_id))

    # Create relationship
    relationship = IOCRelationship(
        source_ioc_id=source_ioc_id,
        target_ioc_id=target_ioc_id,
        relationship_type=relationship_type,
        notes=notes,
        created_by=current_user.id
    )

    try:
        db.session.add(relationship)
        db.session.commit()

        # Audit log
        log = AuditLog(
            user_id=current_user.id,
            action='CREATE',
            resource_type='IOCRelationship',
            resource_id=relationship.id,
            details=f'Created relationship: IOC#{source_ioc_id} {relationship_type} IOC#{target_ioc_id}'
        )
        db.session.add(log)
        db.session.commit()

        flash(f'Relationship created successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating relationship: {str(e)}', 'danger')

    return redirect(url_for('ioc.detail', id=source_ioc_id))


@relationship_bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    """Delete a relationship"""
    relationship = IOCRelationship.query.get_or_404(id)
    source_ioc_id = relationship.source_ioc_id

    # Check permission (creator or admin)
    if not current_user.is_admin() and relationship.created_by != current_user.id:
        flash('You do not have permission to delete this relationship.', 'danger')
        return redirect(url_for('ioc.detail', id=source_ioc_id))

    try:
        # Audit log before deletion
        log = AuditLog(
            user_id=current_user.id,
            action='DELETE',
            resource_type='IOCRelationship',
            resource_id=relationship.id,
            details=f'Deleted relationship: IOC#{relationship.source_ioc_id} {relationship.relationship_type} IOC#{relationship.target_ioc_id}'
        )
        db.session.add(log)

        db.session.delete(relationship)
        db.session.commit()

        flash('Relationship deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting relationship: {str(e)}', 'danger')

    return redirect(url_for('ioc.detail', id=source_ioc_id))


@relationship_bp.route('/search-iocs')
@login_required
def search_iocs():
    """Search IOCs for relationship creation (AJAX endpoint)"""
    from app.models.ioc import IOCType

    query = request.args.get('q', '').strip()
    exclude_id = request.args.get('exclude_id', type=int)
    limit = request.args.get('limit', 10, type=int)

    if not query or len(query) < 2:
        return jsonify([])

    # Search IOCs by value or type name
    iocs = IOC.query.join(IOC.ioc_type).filter(
        db.or_(
            IOC.value.ilike(f'%{query}%'),
            IOCType.name.ilike(f'%{query}%')
        )
    )

    # Exclude specific IOC (usually the source IOC)
    if exclude_id:
        iocs = iocs.filter(IOC.id != exclude_id)

    iocs = iocs.limit(limit).all()

    return jsonify([{
        'id': ioc.id,
        'value': ioc.value,
        'type': ioc.ioc_type.name,
        'severity': ioc.severity,
        'is_active': ioc.is_active
    } for ioc in iocs])
