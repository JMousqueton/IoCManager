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


class DomainEnrichmentCache(db.Model):
    """Cache for Domain enrichment data (WHOIS, DNS records, certificates)"""

    __tablename__ = 'domain_enrichment_cache'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    whois_data = db.Column(db.Text)  # JSON string with WHOIS data
    mx_records = db.Column(db.Text)  # JSON array of MX records
    txt_records = db.Column(db.Text)  # JSON array of TXT records
    ns_records = db.Column(db.Text)  # JSON array of NS records
    a_records = db.Column(db.Text)  # JSON array of A records
    aaaa_records = db.Column(db.Text)  # JSON array of AAAA records
    certificates = db.Column(db.Text)  # JSON array of SSL/TLS certificates
    registration_date = db.Column(db.DateTime)  # Domain registration date
    expiration_date = db.Column(db.DateTime)  # Domain expiration date
    registrar = db.Column(db.String(255))  # Registrar name
    cached_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    def is_expired(self):
        """Check if cache entry is expired"""
        return datetime.utcnow() > self.expires_at

    @staticmethod
    def create_cache_entry(domain, enrichment_data, cache_days=7):
        """Create a new cache entry with expiration"""
        expires_at = datetime.utcnow() + timedelta(days=cache_days)
        return DomainEnrichmentCache(
            domain=domain.lower(),
            whois_data=enrichment_data.get('whois_data'),
            mx_records=enrichment_data.get('mx_records'),
            txt_records=enrichment_data.get('txt_records'),
            ns_records=enrichment_data.get('ns_records'),
            a_records=enrichment_data.get('a_records'),
            aaaa_records=enrichment_data.get('aaaa_records'),
            certificates=enrichment_data.get('certificates'),
            registration_date=enrichment_data.get('registration_date'),
            expiration_date=enrichment_data.get('expiration_date'),
            registrar=enrichment_data.get('registrar'),
            expires_at=expires_at
        )

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'domain': self.domain,
            'whois_data': self.whois_data,
            'mx_records': self.mx_records,
            'txt_records': self.txt_records,
            'ns_records': self.ns_records,
            'a_records': self.a_records,
            'aaaa_records': self.aaaa_records,
            'certificates': self.certificates,
            'registration_date': self.registration_date.isoformat() if self.registration_date else None,
            'expiration_date': self.expiration_date.isoformat() if self.expiration_date else None,
            'registrar': self.registrar,
            'cached_at': self.cached_at.isoformat() if self.cached_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }

    def __repr__(self):
        return f'<DomainEnrichmentCache {self.domain}>'


class URLEnrichmentCache(db.Model):
    """Cache for URL enrichment data (HTTP headers, server info, SSL certificates)"""
    __tablename__ = 'url_enrichment_cache'

    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), unique=True, nullable=False, index=True)
    status_code = db.Column(db.Integer)
    server = db.Column(db.String(500))
    headers = db.Column(db.Text)  # JSON
    technologies = db.Column(db.Text)  # JSON array
    security_headers = db.Column(db.Text)  # JSON
    redirect_url = db.Column(db.String(2048))
    response_time = db.Column(db.Float)
    content_type = db.Column(db.String(200))
    favicon_url = db.Column(db.String(2048))
    favicon_path = db.Column(db.String(500))  # Local path to downloaded favicon
    favicon_sha256 = db.Column(db.String(64))  # SHA256 hash of favicon file
    ssl_certificate = db.Column(db.Text)  # JSON
    cached_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)

    def is_expired(self):
        """Check if cache entry is expired"""
        return datetime.utcnow() > self.expires_at

    @staticmethod
    def create_cache_entry(url, enrichment_data, cache_days=7):
        """Create a new cache entry with expiration"""
        expires_at = datetime.utcnow() + timedelta(days=cache_days)
        return URLEnrichmentCache(
            url=url,
            status_code=enrichment_data.get('status_code'),
            server=enrichment_data.get('server'),
            headers=enrichment_data.get('headers'),
            technologies=enrichment_data.get('technologies'),
            security_headers=enrichment_data.get('security_headers'),
            redirect_url=enrichment_data.get('redirect_url'),
            response_time=enrichment_data.get('response_time'),
            content_type=enrichment_data.get('content_type'),
            favicon_url=enrichment_data.get('favicon_url'),
            favicon_path=enrichment_data.get('favicon_path'),
            favicon_sha256=enrichment_data.get('favicon_sha256'),
            ssl_certificate=enrichment_data.get('ssl_certificate'),
            expires_at=expires_at
        )

    def to_dict(self):
        """Convert to dictionary"""
        return {
            'url': self.url,
            'status_code': self.status_code,
            'server': self.server,
            'headers': self.headers,
            'technologies': self.technologies,
            'security_headers': self.security_headers,
            'redirect_url': self.redirect_url,
            'response_time': self.response_time,
            'content_type': self.content_type,
            'favicon_url': self.favicon_url,
            'favicon_path': self.favicon_path,
            'favicon_sha256': self.favicon_sha256,
            'ssl_certificate': self.ssl_certificate,
            'cached_at': self.cached_at.isoformat() if self.cached_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }

    def __repr__(self):
        return f'<URLEnrichmentCache {self.url}>'
