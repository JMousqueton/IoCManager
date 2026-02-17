"""Notification Service for IOC Lifecycle Management"""

from datetime import datetime
from flask import render_template
from flask_mail import Message
from app import db, mail
from app.models.notification import PendingNotification
from app.models.user import User
from app.models.ioc import IOC


class NotificationService:
    """Handle lifecycle notifications and daily digest emails"""

    # ──────────────────────────────────────────────────────────────
    # Queuing helpers
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def queue_notification(user_id, notification_type, ioc_id, details=None):
        """Add a single pending notification to the queue"""
        notif = PendingNotification(
            user_id=user_id,
            notification_type=notification_type,
            ioc_id=ioc_id,
        )
        if details:
            notif.set_details(details)
        db.session.add(notif)

    @staticmethod
    def queue_for_reviewers(notification_type, ioc, details=None):
        """
        Queue a notification for all reviewers and admins.
        Used when an IOC needs attention (e.g. submitted for review).
        """
        reviewers = User.query.filter(
            User.is_active == True,
            db.or_(User.is_reviewer == True, User.role == 'Admin')
        ).all()
        for reviewer in reviewers:
            # Don't notify the creator if they are also a reviewer
            if reviewer.id == ioc.created_by:
                continue
            NotificationService.queue_notification(
                user_id=reviewer.id,
                notification_type=notification_type,
                ioc_id=ioc.id,
                details=details,
            )

    @staticmethod
    def queue_for_creator(notification_type, ioc, details=None):
        """Queue a notification for the IOC creator"""
        NotificationService.queue_notification(
            user_id=ioc.created_by,
            notification_type=notification_type,
            ioc_id=ioc.id,
            details=details,
        )

    # ──────────────────────────────────────────────────────────────
    # Convenience wrappers for each lifecycle event
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def notify_submitted_for_review(ioc):
        """IOC was submitted for review — notify reviewers/admins"""
        NotificationService.queue_for_reviewers(
            notification_type='pending_review',
            ioc=ioc,
            details={'ioc_value': ioc.value},
        )

    @staticmethod
    def notify_approved(ioc, approver):
        """IOC was approved — notify creator"""
        NotificationService.queue_for_creator(
            notification_type='approved',
            ioc=ioc,
            details={'approved_by': approver.username},
        )

    @staticmethod
    def notify_rejected(ioc, reviewer, reason):
        """IOC was rejected — notify creator"""
        NotificationService.queue_for_creator(
            notification_type='rejected',
            ioc=ioc,
            details={'rejected_by': reviewer.username, 'reason': reason},
        )

    @staticmethod
    def notify_archived(ioc, archiver, reason=None):
        """IOC was archived — notify creator"""
        NotificationService.queue_for_creator(
            notification_type='archived',
            ioc=ioc,
            details={'archived_by': archiver.username, 'reason': reason or ''},
        )

    # ──────────────────────────────────────────────────────────────
    # Badge count for reviewers
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def pending_review_count():
        """Number of IOCs currently in 'review' status"""
        return IOC.query.filter(IOC.status == 'review').count()

    # ──────────────────────────────────────────────────────────────
    # Daily digest
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def send_daily_digest(app):
        """
        Process all queued pending notifications and send per-user digest emails.
        Called by the cron/scheduler script.
        """
        with app.app_context():
            # Group notifications by user
            notifications = PendingNotification.query.order_by(
                PendingNotification.user_id, PendingNotification.created_at
            ).all()

            if not notifications:
                print("[Digest] No pending notifications — nothing to send")
                return

            # Build per-user buckets
            user_notifs = {}
            for n in notifications:
                user_notifs.setdefault(n.user_id, []).append(n)

            sent = 0
            failed = 0

            for user_id, user_notifications in user_notifs.items():
                user = User.query.get(user_id)
                if not user or not user.email:
                    continue

                try:
                    # Build grouped summary for the template
                    groups = NotificationService._group_notifications(user_notifications)

                    html = render_template(
                        'email/lifecycle_digest.html',
                        user=user,
                        groups=groups,
                        total=len(user_notifications),
                        generated_at=datetime.utcnow(),
                    )

                    subject = f"[IOC Manager] Daily Lifecycle Digest — {len(user_notifications)} notification(s)"
                    msg = Message(
                        subject=subject,
                        recipients=[user.email],
                        html=html,
                    )
                    mail.send(msg)

                    # Delete sent notifications
                    for n in user_notifications:
                        db.session.delete(n)
                    db.session.commit()
                    sent += 1

                except Exception as e:
                    print(f"[Digest] Failed to send digest to {user.email}: {e}")
                    db.session.rollback()
                    failed += 1

            print(f"[Digest] Sent {sent} digests, {failed} failed")

    @staticmethod
    def _group_notifications(notifications):
        """
        Group a list of PendingNotification objects by type.
        Returns a dict: { notification_type: [notif, ...] }
        """
        groups = {}
        for n in notifications:
            groups.setdefault(n.notification_type, []).append(n)
        return groups
