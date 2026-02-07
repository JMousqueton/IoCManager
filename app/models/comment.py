"""IOC Comment Model - Support threaded discussions on IOCs"""

from datetime import datetime
from app import db
import re


class Comment(db.Model):
    """Comments on IOCs with threading support"""

    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comments.id', ondelete='CASCADE'), nullable=True, index=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=True, onupdate=datetime.utcnow)

    # Relationships
    ioc = db.relationship('IOC', backref=db.backref('comments', lazy='dynamic', cascade='all, delete-orphan'))
    author = db.relationship('User', backref=db.backref('comments', lazy='dynamic'))

    # Self-referential relationship for threading
    replies = db.relationship(
        'Comment',
        backref=db.backref('parent', remote_side=[id]),
        lazy='dynamic',
        cascade='all, delete-orphan'
    )

    def __repr__(self):
        return f'<Comment {self.id} by User {self.user_id} on IOC {self.ioc_id}>'

    def is_reply(self):
        """Check if this comment is a reply to another comment"""
        return self.parent_id is not None

    def get_replies(self):
        """Get all direct replies to this comment"""
        return self.replies.order_by(Comment.created_at.asc()).all()

    def get_thread(self):
        """Get the full thread hierarchy starting from this comment"""
        thread = [self]
        for reply in self.get_replies():
            thread.extend(reply.get_thread())
        return thread

    def extract_mentions(self):
        """Extract @username mentions from comment content

        Returns:
            list: List of mentioned usernames (without @ symbol)
        """
        # Match @username pattern (alphanumeric, underscore, hyphen)
        mentions = re.findall(r'@([\w-]+)', self.content)
        return list(set(mentions))  # Remove duplicates

    def get_mentioned_users(self):
        """Get User objects for all @mentions in this comment

        Returns:
            list: List of User objects that were mentioned
        """
        from app.models.user import User

        usernames = self.extract_mentions()
        if not usernames:
            return []

        return User.query.filter(User.username.in_(usernames)).all()

    def is_edited(self):
        """Check if comment has been edited"""
        return self.updated_at is not None

    def can_edit(self, user):
        """Check if a user can edit this comment

        Args:
            user: User object

        Returns:
            bool: True if user can edit this comment
        """
        # Author can edit their own comments
        # Admins can edit any comment
        return user.id == self.user_id or user.is_admin()

    def can_delete(self, user):
        """Check if a user can delete this comment

        Args:
            user: User object

        Returns:
            bool: True if user can delete this comment
        """
        # Author can delete their own comments
        # Admins can delete any comment
        return user.id == self.user_id or user.is_admin()
