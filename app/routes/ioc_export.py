"""IOC Export routes - STIX/TAXII format"""

from flask import Blueprint, jsonify, request, make_response
from flask_login import login_required, current_user
from app.models.ioc import IOC
from app.services.stix_export import STIXExporter
import json

export_bp = Blueprint('ioc_export', __name__, url_prefix='/iocs/export')


@export_bp.route('/<int:id>/stix')
@login_required
def export_single_stix(id):
    """Export a single IOC in STIX 2.1 format"""

    ioc = IOC.query.get_or_404(id)

    # Create STIX export
    exporter = STIXExporter()
    stix_bundle = exporter.export_ioc(ioc)

    # Create JSON response with download headers
    response = make_response(json.dumps(stix_bundle, indent=2))
    response.headers['Content-Type'] = 'application/stix+json;version=2.1'
    response.headers['Content-Disposition'] = f'attachment; filename=ioc_{ioc.id}_stix.json'

    # Log export
    from app.models.audit import AuditLog
    from app import db

    log = AuditLog(
        user_id=current_user.id,
        action='EXPORT',
        resource_type='IOC',
        resource_id=ioc.id,
        details=f'Exported IOC in STIX 2.1 format: {ioc.value}'
    )
    db.session.add(log)
    db.session.commit()

    return response


@export_bp.route('/bulk/stix', methods=['POST'])
@login_required
def export_bulk_stix():
    """Export multiple IOCs in STIX 2.1 format"""

    # Get IOC IDs from request
    data = request.get_json()
    ioc_ids = data.get('ioc_ids', [])

    if not ioc_ids:
        return jsonify({'error': 'No IOC IDs provided'}), 400

    # Fetch IOCs
    iocs = IOC.query.filter(IOC.id.in_(ioc_ids)).all()

    if not iocs:
        return jsonify({'error': 'No IOCs found'}), 404

    # Create STIX export
    exporter = STIXExporter()
    stix_bundle = exporter.export_iocs(iocs)

    # Create JSON response with download headers
    response = make_response(json.dumps(stix_bundle, indent=2))
    response.headers['Content-Type'] = 'application/stix+json;version=2.1'
    response.headers['Content-Disposition'] = f'attachment; filename=iocs_bulk_stix.json'

    # Log export
    from app.models.audit import AuditLog
    from app import db

    log = AuditLog(
        user_id=current_user.id,
        action='EXPORT',
        resource_type='IOC',
        resource_id=None,
        details=f'Exported {len(iocs)} IOCs in STIX 2.1 format'
    )
    db.session.add(log)
    db.session.commit()

    return response


@export_bp.route('/all/stix')
@login_required
def export_all_stix():
    """Export all active IOCs in STIX 2.1 format"""

    # Get filter parameters from query string
    ioc_type_id = request.args.get('ioc_type_id', type=int)
    severity = request.args.get('severity')
    tlp = request.args.get('tlp')
    is_active = request.args.get('is_active', 'True')

    # Build query
    query = IOC.query

    if ioc_type_id:
        query = query.filter_by(ioc_type_id=ioc_type_id)

    if severity:
        query = query.filter_by(severity=severity)

    if tlp:
        query = query.filter_by(tlp=tlp)

    if is_active == 'True':
        query = query.filter_by(is_active=True)

    iocs = query.all()

    if not iocs:
        return jsonify({'error': 'No IOCs found matching criteria'}), 404

    # Create STIX export
    exporter = STIXExporter()
    stix_bundle = exporter.export_iocs(iocs)

    # Create JSON response with download headers
    response = make_response(json.dumps(stix_bundle, indent=2))
    response.headers['Content-Type'] = 'application/stix+json;version=2.1'
    response.headers['Content-Disposition'] = f'attachment; filename=iocs_all_stix.json'

    # Log export
    from app.models.audit import AuditLog
    from app import db

    log = AuditLog(
        user_id=current_user.id,
        action='EXPORT',
        resource_type='IOC',
        resource_id=None,
        details=f'Exported {len(iocs)} IOCs (all) in STIX 2.1 format'
    )
    db.session.add(log)
    db.session.commit()

    return response
