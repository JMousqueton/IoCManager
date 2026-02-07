"""IOC Relationship model for linking related IOCs"""

from datetime import datetime
from app import db


class IOCRelationship(db.Model):
    """Model for relationships between IOCs"""

    __tablename__ = 'ioc_relationships'

    id = db.Column(db.Integer, primary_key=True)
    source_ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id'), nullable=False, index=True)
    target_ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id'), nullable=False, index=True)
    relationship_type = db.Column(db.String(50), nullable=False, index=True)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))

    # Relationships
    source_ioc = db.relationship('IOC', foreign_keys=[source_ioc_id], backref='outgoing_relationships')
    target_ioc = db.relationship('IOC', foreign_keys=[target_ioc_id], backref='incoming_relationships')
    creator = db.relationship('User', backref='created_relationships')

    # Relationship type constants
    RESOLVES_TO = 'resolves_to'  # Domain/URL → IP
    CONTAINS = 'contains'  # URL → Domain
    DOWNLOADS_FROM = 'downloads_from'  # Hash → URL
    COMMUNICATES_WITH = 'communicates_with'  # IP ↔ IP, Domain ↔ Domain
    DROPS = 'drops'  # Hash → Hash (malware drops file)
    CONNECTS_TO = 'connects_to'  # Hash → IP/Domain
    RELATED_TO = 'related_to'  # Generic relationship
    PART_OF_CAMPAIGN = 'part_of_campaign'  # Multiple IOCs → Campaign
    DISTRIBUTES = 'distributes'  # URL/Domain → Hash
    HOSTS = 'hosts'  # IP → Domain/URL

    RELATIONSHIP_TYPES = {
        RESOLVES_TO: {'label': 'Resolves To', 'icon': 'bi-arrow-right-circle', 'reverse': 'resolved_by'},
        CONTAINS: {'label': 'Contains', 'icon': 'bi-box-arrow-in-down', 'reverse': 'contained_in'},
        DOWNLOADS_FROM: {'label': 'Downloads From', 'icon': 'bi-download', 'reverse': 'distributes'},
        COMMUNICATES_WITH: {'label': 'Communicates With', 'icon': 'bi-arrow-left-right', 'bidirectional': True},
        DROPS: {'label': 'Drops', 'icon': 'bi-file-earmark-plus', 'reverse': 'dropped_by'},
        CONNECTS_TO: {'label': 'Connects To', 'icon': 'bi-plug', 'reverse': 'connected_from'},
        RELATED_TO: {'label': 'Related To', 'icon': 'bi-link-45deg', 'bidirectional': True},
        PART_OF_CAMPAIGN: {'label': 'Part of Campaign', 'icon': 'bi-collection', 'reverse': 'includes'},
        DISTRIBUTES: {'label': 'Distributes', 'icon': 'bi-share', 'reverse': 'downloaded_from'},
        HOSTS: {'label': 'Hosts', 'icon': 'bi-server', 'reverse': 'hosted_on'},
    }

    def to_dict(self):
        """Convert relationship to dictionary"""
        return {
            'id': self.id,
            'source_ioc_id': self.source_ioc_id,
            'target_ioc_id': self.target_ioc_id,
            'relationship_type': self.relationship_type,
            'relationship_label': self.get_relationship_label(),
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'created_by': self.creator.username if self.creator else None,
        }

    def get_relationship_label(self):
        """Get human-readable label for relationship type"""
        rel_info = self.RELATIONSHIP_TYPES.get(self.relationship_type, {})
        return rel_info.get('label', self.relationship_type)

    def get_relationship_icon(self):
        """Get Bootstrap icon for relationship type"""
        rel_info = self.RELATIONSHIP_TYPES.get(self.relationship_type, {})
        return rel_info.get('icon', 'bi-link')

    def is_bidirectional(self):
        """Check if relationship type is bidirectional"""
        rel_info = self.RELATIONSHIP_TYPES.get(self.relationship_type, {})
        return rel_info.get('bidirectional', False)

    def get_reverse_label(self):
        """Get reverse relationship label"""
        rel_info = self.RELATIONSHIP_TYPES.get(self.relationship_type, {})
        if self.is_bidirectional():
            return rel_info.get('label', self.relationship_type)
        return rel_info.get('reverse', f"reverse_{self.relationship_type}")

    def __repr__(self):
        return f'<IOCRelationship {self.source_ioc_id} -{self.relationship_type}-> {self.target_ioc_id}>'
