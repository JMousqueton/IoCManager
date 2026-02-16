"""Operating System model for hash IOCs"""

from app import db
from datetime import datetime


class OperatingSystem(db.Model):
    """Operating System for hash-type IOCs"""
    __tablename__ = 'operating_systems'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    icon = db.Column(db.String(50), nullable=True)  # Font Awesome icon class
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship with IOCs
    iocs = db.relationship('IOC', back_populates='operating_system', lazy='dynamic')

    def __repr__(self):
        return f'<OperatingSystem {self.name}>'

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'icon': self.icon,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
