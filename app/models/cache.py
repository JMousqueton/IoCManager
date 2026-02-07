"""Cache models for external service responses"""

from datetime import datetime, timedelta
from app import db


class VirusTotalCache(db.Model):
    """Cache for VirusTotal API responses"""

    __tablename__ = 'virustotal_cache'

    id = db.Column(db.Integer, primary_key=True)
    hash_value = db.Column(db.String(64), unique=True, nullable=False, index=True)
    hash_type = db.Column(db.String(10), nullable=False)  # MD5, SHA1, SHA256
    response_data = db.Column(db.Text, nullable=False)  # JSON string
    cached_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    # Constraints
    __table_args__ = (
        db.CheckConstraint("hash_type IN ('MD5', 'SHA1', 'SHA256')", name='check_hash_type'),
    )

    def is_expired(self):
        """Check if cache entry is expired"""
        return datetime.utcnow() > self.expires_at

    @staticmethod
    def create_cache_entry(hash_value, hash_type, response_data, cache_days=7):
        """Create a new cache entry with expiration"""
        expires_at = datetime.utcnow() + timedelta(days=cache_days)
        return VirusTotalCache(
            hash_value=hash_value.lower(),
            hash_type=hash_type.upper(),
            response_data=response_data,
            expires_at=expires_at
        )

    def __repr__(self):
        return f'<VirusTotalCache {self.hash_type}:{self.hash_value[:16]}...>'


class ASLookupCache(db.Model):
    """Cache for Autonomous System (AS) lookup responses"""

    __tablename__ = 'as_lookup_cache'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)  # IPv6 max length
    ip_version = db.Column(db.Integer, nullable=False)  # 4 or 6
    asn = db.Column(db.Integer)  # Autonomous System Number
    as_description = db.Column(db.Text)  # AS organization name
    country = db.Column(db.String(2))  # ISO country code
    response_data = db.Column(db.Text)  # Full JSON response
    cached_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    # Constraints
    __table_args__ = (
        db.CheckConstraint("ip_version IN (4, 6)", name='check_ip_version'),
    )

    def is_expired(self):
        """Check if cache entry is expired"""
        return datetime.utcnow() > self.expires_at

    @staticmethod
    def create_cache_entry(ip_address, ip_version, asn, as_description, country, response_data, cache_days=30):
        """Create a new cache entry with expiration"""
        expires_at = datetime.utcnow() + timedelta(days=cache_days)
        return ASLookupCache(
            ip_address=ip_address,
            ip_version=ip_version,
            asn=asn,
            as_description=as_description,
            country=country,
            response_data=response_data,
            expires_at=expires_at
        )

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'ip_address': self.ip_address,
            'ip_version': self.ip_version,
            'asn': self.asn,
            'as_description': self.as_description,
            'country': self.country,
            'cached_at': self.cached_at.isoformat() if self.cached_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }

    def __repr__(self):
        return f'<ASLookupCache {self.ip_address} -> AS{self.asn}>'


class URLScanCache(db.Model):
    """Cache for URLScan.io API responses"""

    __tablename__ = 'urlscan_cache'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False, index=True)  # URLs can be long
    response_data = db.Column(db.Text, nullable=False)  # JSON string
    cached_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    def is_expired(self):
        """Check if cache entry is expired"""
        return datetime.utcnow() > self.expires_at

    @staticmethod
    def create_cache_entry(url, response_data, cache_days=7):
        """Create a new cache entry with expiration"""
        expires_at = datetime.utcnow() + timedelta(days=cache_days)
        return URLScanCache(
            url=url,
            response_data=response_data,
            expires_at=expires_at
        )

    def __repr__(self):
        return f'<URLScanCache {self.url[:50]}...>'
