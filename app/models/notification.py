"""Pending notification model for lifecycle digest emails"""

import json
from datetime import datetime
from app import db


class PendingNotification(db.Model):
    """Queue for pending lifecycle notifications (batched into daily digest)"""

    __tablename__ = 'pending_notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True)
    notification_type = db.Column(db.String(50), nullable=False)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id', ondelete='CASCADE'), nullable=False)
    details = db.Column(db.Text, nullable=True)  # JSON string for extra data
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Notification types:
    #   'submitted_for_review'  - creator notified when IOC moves to review
    #   'approved'              - creator notified when IOC is approved
    #   'rejected'              - creator notified when IOC is rejected
    #   'archived'              - creator notified when IOC is archived
    #   'pending_review'        - reviewer notified of pending items

    # Relationships
    user = db.relationship('User', backref=db.backref('pending_notifications', lazy='dynamic'))
    ioc = db.relationship('IOC', backref=db.backref('pending_notifications', lazy='dynamic'))

    def get_details(self):
        """Return details dict"""
        if not self.details:
            return {}
        try:
            return json.loads(self.details)
        except Exception:
            return {}

    def set_details(self, data: dict):
        """Store details as JSON"""
        self.details = json.dumps(data)

    def __repr__(self):
        return f'<PendingNotification type={self.notification_type} user_id={self.user_id} ioc_id={self.ioc_id}>'
