"""IOC and IOCType models"""

from datetime import datetime, timedelta
from app import db


class IOCType(db.Model):
    """IOC Type reference table"""

    __tablename__ = 'ioc_types'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text)
    validation_regex = db.Column(db.Text)
    icon = db.Column(db.String(50))

    # Relationships
    iocs = db.relationship('IOC', backref='ioc_type', lazy='dynamic')

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'icon': self.icon
        }

    def __repr__(self):
        return f'<IOCType {self.name}>'


# Association table for many-to-many relationship between IOCs and Tags
class IOCTag(db.Model):
    """Junction table for IOC-Tag many-to-many relationship"""

    __tablename__ = 'ioc_tags'

    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id', ondelete='CASCADE'), primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.id', ondelete='CASCADE'), primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f'<IOCTag ioc_id={self.ioc_id} tag_id={self.tag_id}>'


class IOC(db.Model):
    """Indicator of Compromise model"""

    __tablename__ = 'iocs'

    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Text, nullable=False, index=True)
    ioc_type_id = db.Column(db.Integer, db.ForeignKey('ioc_types.id'), nullable=False, index=True)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    confidence = db.Column(db.Integer)
    source = db.Column(db.String(255))
    tlp = db.Column(db.String(20))
    first_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    false_positive = db.Column(db.Boolean, default=False, nullable=False)
    notes = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # Enrichment data (populated from external sources)
    enrichment_data = db.Column(db.Text)  # JSON string

    # Expiration fields
    expires_at = db.Column(db.DateTime, nullable=True, index=True)  # Nullable for backward compatibility
    expired_reason = db.Column(db.String(100), nullable=True)  # 'auto_expired', 'manual', etc.

    # Review flag - allows any user to edit when set to True
    needs_review = db.Column(db.Boolean, default=False, nullable=False, index=True)

    # Operating System (for hash-type IOCs)
    operating_system_id = db.Column(db.Integer, db.ForeignKey('operating_systems.id'), nullable=True)

    # Relationships
    tags = db.relationship('Tag', secondary='ioc_tags', backref=db.backref('iocs', lazy='dynamic'))
    operating_system = db.relationship('OperatingSystem', back_populates='iocs')

    # Constraints
    __table_args__ = (
        db.CheckConstraint("severity IN ('Low', 'Medium', 'High', 'Critical')", name='check_severity'),
        db.CheckConstraint("tlp IN ('WHITE', 'GREEN', 'AMBER', 'RED')", name='check_tlp'),
        db.CheckConstraint("confidence >= 0 AND confidence <= 100", name='check_confidence'),
        db.UniqueConstraint('value', 'ioc_type_id', name='unique_ioc_value_type'),
    )

    def update_last_seen(self):
        """Update last seen timestamp"""
        self.last_seen = datetime.utcnow()

    def mark_false_positive(self):
        """Mark as false positive"""
        self.false_positive = True
        self.is_active = False

    def add_tag(self, tag):
        """Add a tag to this IOC"""
        if tag not in self.tags:
            self.tags.append(tag)

    def remove_tag(self, tag):
        """Remove a tag from this IOC"""
        if tag in self.tags:
            self.tags.remove(tag)

    def get_enrichment(self):
        """Get enrichment data as dictionary"""
        if not self.enrichment_data:
            return {}
        import json
        try:
            return json.loads(self.enrichment_data)
        except:
            return {}

    def set_enrichment(self, data):
        """Set enrichment data from dictionary"""
        import json
        self.enrichment_data = json.dumps(data)

    def is_expired(self):
        """Check if IOC is expired"""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    def set_expiration(self, days_from_now):
        """Set expiration date relative to now"""
        if days_from_now:
            self.expires_at = datetime.utcnow() + timedelta(days=days_from_now)
        else:
            self.expires_at = None

    def extend_expiration(self, additional_days):
        """Extend expiration by additional days"""
        if self.expires_at:
            self.expires_at = self.expires_at + timedelta(days=additional_days)
        else:
            self.set_expiration(additional_days)

    def to_dict(self, include_enrichment=False):
        """Convert to dictionary"""
        result = {
            'id': self.id,
            'value': self.value,
            'type': self.ioc_type.name if self.ioc_type else None,
            'type_id': self.ioc_type_id,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'source': self.source,
            'tlp': self.tlp,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'is_active': self.is_active,
            'false_positive': self.false_positive,
            'notes': self.notes,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'tags': [tag.name for tag in self.tags]
        }

        if include_enrichment:
            result['enrichment'] = self.get_enrichment()

        return result

    def __repr__(self):
        type_name = self.ioc_type.name if self.ioc_type else 'Unknown'
        return f'<IOC {type_name}: {self.value[:50]}>'
