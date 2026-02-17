#!/usr/bin/env python3
"""
Enforce IOC retention policies:
  - Auto-archive IOCs that have been in 'draft' for > DRAFT_RETENTION_DAYS days
  - Auto-archive active IOCs whose expires_at has passed (existing logic)
  - Remove notifications older than NOTIFICATION_RETENTION_DAYS days

Configuration (via .env or environment variables):
  DRAFT_RETENTION_DAYS          Days before draft IOCs are auto-archived (default: 30)
  NOTIFICATION_RETENTION_DAYS   Days before processed notifications are purged (default: 7)

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/enforce_retention_policies.py

Cron example (daily at 02:00):
    0 2 * * * cd /opt/iocmanager && PYTHONPATH=. venv/bin/python3 scripts/enforce_retention_policies.py >> /var/log/iocmanager-retention.log 2>&1
"""

import sys
import os
from datetime import datetime, timedelta
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app import create_app, db
from app.models.ioc import IOC
from app.models.audit import AuditLog
from app.models.notification import PendingNotification

DRAFT_RETENTION_DAYS = int(os.environ.get('DRAFT_RETENTION_DAYS', 30))
NOTIFICATION_RETENTION_DAYS = int(os.environ.get('NOTIFICATION_RETENTION_DAYS', 7))


def archive_stale_drafts(app):
    """Archive draft IOCs that haven't been updated within retention period"""
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=DRAFT_RETENTION_DAYS)
        stale_drafts = IOC.query.filter(
            IOC.status == 'draft',
            IOC.updated_at < cutoff
        ).all()

        count = 0
        for ioc in stale_drafts:
            reason = f'Auto-archived: draft for more than {DRAFT_RETENTION_DAYS} days'
            ioc.status = 'archived'
            ioc.is_active = False
            ioc.archived_at = datetime.utcnow()
            ioc.archived_reason = reason

            log = AuditLog(
                user_id=None,
                action='UPDATE',
                resource_type='IOC',
                resource_id=ioc.id,
                details=reason
            )
            db.session.add(log)
            count += 1

        if count:
            db.session.commit()
        print(f"[Retention] Archived {count} stale draft IOC(s)")
        return count


def archive_expired_active(app):
    """Archive active IOCs whose expires_at has passed"""
    with app.app_context():
        now = datetime.utcnow()
        expired = IOC.query.filter(
            IOC.status == 'active',
            IOC.expires_at.isnot(None),
            IOC.expires_at < now
        ).all()

        count = 0
        for ioc in expired:
            reason = 'Auto-archived: expiration date reached'
            ioc.status = 'archived'
            ioc.is_active = False
            ioc.expired_reason = 'auto_expired'
            ioc.archived_at = now
            ioc.archived_reason = reason

            log = AuditLog(
                user_id=None,
                action='UPDATE',
                resource_type='IOC',
                resource_id=ioc.id,
                details=reason
            )
            db.session.add(log)
            count += 1

        if count:
            db.session.commit()
        print(f"[Retention] Archived {count} expired active IOC(s)")
        return count


def purge_old_notifications(app):
    """Delete pending notifications older than retention period"""
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=NOTIFICATION_RETENTION_DAYS)
        count = PendingNotification.query.filter(
            PendingNotification.created_at < cutoff
        ).delete()
        db.session.commit()
        print(f"[Retention] Purged {count} stale notification(s)")
        return count


if __name__ == '__main__':
    app = create_app()
    print(f"[Retention] Starting retention enforcement at {datetime.utcnow().isoformat()}")
    print(f"[Retention] Draft retention: {DRAFT_RETENTION_DAYS} days")
    print(f"[Retention] Notification retention: {NOTIFICATION_RETENTION_DAYS} days")

    archive_stale_drafts(app)
    archive_expired_active(app)
    purge_old_notifications(app)

    print(f"[Retention] Done.")
