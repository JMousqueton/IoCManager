"""Main routes blueprint"""

from flask import Blueprint, render_template, send_from_directory, current_app
from flask_login import login_required, current_user
from app.models.ioc import IOC, IOCType
from app.models.user import User
from app import db
from sqlalchemy import func
import os

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
@main_bp.route('/index')
@login_required
def index():
    """Dashboard/home page"""

    # Get statistics
    stats = {
        'total_iocs': IOC.query.count(),
        'active_iocs': IOC.query.filter_by(is_active=True).count(),
        'false_positives': IOC.query.filter_by(false_positive=True).count(),
        'total_users': User.query.count(),
        'critical_iocs': IOC.query.filter_by(severity='Critical', is_active=True).count(),
        'high_iocs': IOC.query.filter_by(severity='High', is_active=True).count(),
    }

    # Get recent IOCs
    recent_iocs = IOC.query.filter_by(is_active=True).order_by(IOC.created_at.desc()).limit(10).all()

    # Get IOCs by type
    iocs_by_type = db.session.query(
        IOCType.name,
        func.count(IOC.id).label('count')
    ).join(IOC).filter(IOC.is_active == True).group_by(IOCType.name).all()

    # Get IOCs by severity
    iocs_by_severity = db.session.query(
        IOC.severity,
        func.count(IOC.id).label('count')
    ).filter(IOC.is_active == True).group_by(IOC.severity).all()

    return render_template('main/index.html',
                           stats=stats,
                           recent_iocs=recent_iocs,
                           iocs_by_type=iocs_by_type,
                           iocs_by_severity=iocs_by_severity)


@main_bp.route('/cached/<path:filename>')
@login_required
def serve_cached_file(filename):
    """Serve cached files (favicons, etc.)"""
    # Ensure the path is safe and within the cached directory
    cached_dir = os.path.join(current_app.root_path, '..', 'cached')
    return send_from_directory(cached_dir, filename)


@main_bp.route('/about')
def about():
    """About page"""
    return render_template('main/about.html')


@main_bp.route('/shared_ioc/<token>')
def shared_ioc(token):
    """Public shared view of an IOC using an unguessable token (no login required)"""
    ioc = IOC.query.filter_by(share_token=token).first_or_404()
    return render_template('ioc/shared.html', ioc=ioc)
