"""Main routes blueprint"""

from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app.models.ioc import IOC, IOCType
from app.models.user import User
from app import db
from sqlalchemy import func

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


@main_bp.route('/about')
def about():
    """About page"""
    return render_template('main/about.html')
