"""Report Generation Service for Email Reports"""

from datetime import datetime, timedelta
from flask import render_template
from flask_mail import Message
from sqlalchemy import func, and_
from app import db, mail
from app.models.ioc import IOC, IOCType
from app.models.audit import AuditLog
from app.models.user import User


class ReportGenerator:
    """Generate IOC reports for email distribution"""

    @staticmethod
    def generate_daily_report(app):
        """
        Generate daily IOC report

        Args:
            app: Flask application instance

        Returns:
            tuple: (subject, html_content)
        """
        with app.app_context():
            # Calculate date range (last 24 hours)
            now = datetime.utcnow()
            yesterday = now - timedelta(days=1)

            # Gather statistics
            stats = {}

            # New IOCs today
            stats['new_iocs_today'] = IOC.query.filter(
                IOC.created_at >= yesterday
            ).count()

            # Total active IOCs
            stats['total_active'] = IOC.query.filter(
                IOC.is_active == True
            ).count()

            # Enrichment success rate
            total_iocs = IOC.query.count()
            enriched_iocs = IOC.query.filter(
                IOC.enrichment_data.isnot(None)
            ).count()
            stats['enrichment_rate'] = round((enriched_iocs / total_iocs * 100) if total_iocs > 0 else 0, 1)

            # Get new IOCs added today
            new_iocs = IOC.query.filter(
                IOC.created_at >= yesterday
            ).order_by(IOC.created_at.desc()).limit(20).all()

            # Get high severity IOCs from last 24h
            high_severity_iocs = IOC.query.filter(
                and_(
                    IOC.created_at >= yesterday,
                    IOC.severity.in_(['High', 'Critical'])
                )
            ).order_by(IOC.severity.desc(), IOC.created_at.desc()).limit(10).all()

            # IOC distribution by type
            type_distribution = db.session.query(
                IOCType.name,
                func.count(IOC.id).label('count')
            ).join(IOC.ioc_type).filter(
                IOC.is_active == True
            ).group_by(IOCType.name).order_by(func.count(IOC.id).desc()).all()

            total_count = sum(item.count for item in type_distribution)
            type_dist_with_pct = [{
                'name': item.name,
                'count': item.count,
                'percentage': round((item.count / total_count * 100) if total_count > 0 else 0, 1)
            } for item in type_distribution]

            # Render template
            html_content = render_template(
                'email/daily_report.html',
                report_date=now.strftime('%Y-%m-%d'),
                stats=stats,
                new_iocs=new_iocs,
                high_severity_iocs=high_severity_iocs,
                type_distribution=type_dist_with_pct
            )

            subject = f"IOC Manager Daily Report - {now.strftime('%Y-%m-%d')}"

            return subject, html_content

    @staticmethod
    def generate_weekly_report(app):
        """
        Generate weekly IOC report

        Args:
            app: Flask application instance

        Returns:
            tuple: (subject, html_content)
        """
        with app.app_context():
            # Calculate date ranges
            now = datetime.utcnow()
            week_start = now - timedelta(days=7)
            two_weeks_ago = now - timedelta(days=14)

            # Gather statistics
            stats = {}

            # New IOCs this week
            stats['new_iocs_week'] = IOC.query.filter(
                IOC.created_at >= week_start
            ).count()

            # New IOCs last week (for comparison)
            new_iocs_last_week = IOC.query.filter(
                and_(
                    IOC.created_at >= two_weeks_ago,
                    IOC.created_at < week_start
                )
            ).count()

            # Calculate change percentage
            if new_iocs_last_week > 0:
                stats['new_iocs_change'] = round(
                    ((stats['new_iocs_week'] - new_iocs_last_week) / new_iocs_last_week * 100), 1
                )
            else:
                stats['new_iocs_change'] = 0

            # Total active IOCs
            stats['total_active'] = IOC.query.filter(IOC.is_active == True).count()

            # Critical and High count
            stats['critical_count'] = IOC.query.filter(
                and_(IOC.is_active == True, IOC.severity == 'Critical')
            ).count()
            stats['high_count'] = IOC.query.filter(
                and_(IOC.is_active == True, IOC.severity == 'High')
            ).count()

            # Enriched IOCs
            stats['enriched_count'] = IOC.query.filter(
                IOC.enrichment_data.isnot(None)
            ).count()
            total_iocs = IOC.query.count()
            stats['enrichment_rate'] = round(
                (stats['enriched_count'] / total_iocs * 100) if total_iocs > 0 else 0, 1
            )

            # Active users this week
            stats['active_users'] = db.session.query(func.count(func.distinct(AuditLog.user_id))).filter(
                AuditLog.timestamp >= week_start
            ).scalar()

            # Total actions
            stats['total_actions'] = AuditLog.query.filter(
                AuditLog.timestamp >= week_start
            ).count()

            # Severity trends
            severity_trends = []
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                this_week = IOC.query.filter(
                    and_(IOC.created_at >= week_start, IOC.severity == severity)
                ).count()
                last_week = IOC.query.filter(
                    and_(
                        IOC.created_at >= two_weeks_ago,
                        IOC.created_at < week_start,
                        IOC.severity == severity
                    )
                ).count()
                severity_trends.append({
                    'name': severity,
                    'this_week': this_week,
                    'last_week': last_week,
                    'change': this_week - last_week
                })

            # Top IOC types
            top_ioc_types = db.session.query(
                IOCType.name,
                func.count(IOC.id).label('count')
            ).join(IOC.ioc_type).filter(
                and_(IOC.created_at >= week_start, IOC.is_active == True)
            ).group_by(IOCType.name).order_by(func.count(IOC.id).desc()).limit(10).all()

            total_count = sum(item.count for item in top_ioc_types)
            top_ioc_types_with_pct = [{
                'name': item.name,
                'count': item.count,
                'percentage': round((item.count / total_count * 100) if total_count > 0 else 0, 1)
            } for item in top_ioc_types]

            # Top sources
            top_sources = db.session.query(
                func.coalesce(IOC.source, 'Unknown').label('name'),
                func.count(IOC.id).label('count')
            ).filter(
                IOC.created_at >= week_start
            ).group_by('name').order_by(func.count(IOC.id).desc()).limit(10).all()

            # Most active users
            most_active_users = db.session.query(
                User.username,
                func.count(IOC.id).label('iocs_created'),
                func.count(AuditLog.id).label('total_actions')
            ).outerjoin(IOC, IOC.created_by == User.id).outerjoin(
                AuditLog, AuditLog.user_id == User.id
            ).filter(
                IOC.created_at >= week_start
            ).group_by(User.username).order_by(
                func.count(IOC.id).desc()
            ).limit(5).all()

            # IOCs expiring soon (next 7 days)
            next_week = now + timedelta(days=7)
            expiring_soon = IOC.query.filter(
                and_(
                    IOC.expires_at.isnot(None),
                    IOC.expires_at >= now,
                    IOC.expires_at <= next_week,
                    IOC.is_active == True
                )
            ).order_by(IOC.expires_at.asc()).limit(10).all()

            # Render template
            html_content = render_template(
                'email/weekly_report.html',
                report_date=now.strftime('%Y-%m-%d'),
                week_start=week_start.strftime('%Y-%m-%d'),
                week_end=now.strftime('%Y-%m-%d'),
                stats=stats,
                severity_trends=severity_trends,
                top_ioc_types=top_ioc_types_with_pct,
                top_sources=top_sources,
                most_active_users=most_active_users,
                expiring_soon=expiring_soon
            )

            subject = f"IOC Manager Weekly Report - Week of {week_start.strftime('%Y-%m-%d')}"

            return subject, html_content

    @staticmethod
    def send_report(app, subject, html_content, recipients):
        """
        Send email report

        Args:
            app: Flask application instance
            subject: Email subject
            html_content: HTML email content
            recipients: List of email addresses

        Returns:
            bool: True if sent successfully, False otherwise
        """
        with app.app_context():
            try:
                msg = Message(
                    subject=subject,
                    recipients=recipients,
                    html=html_content,
                    sender=app.config['MAIL_DEFAULT_SENDER']
                )
                mail.send(msg)
                return True
            except Exception as e:
                print(f"Error sending email report: {e}")
                return False
