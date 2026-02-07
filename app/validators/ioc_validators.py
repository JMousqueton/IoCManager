"""
IOC Validators
Validation functions for different types of Indicators of Compromise
"""

import re
import validators
from email_validator import validate_email as email_validate, EmailNotValidError
import dns.resolver


# Hash validation patterns
MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')


def validate_md5(value):
    """
    Validate MD5 hash (32 hexadecimal characters)

    Args:
        value: String to validate

    Returns:
        bool: True if valid MD5, False otherwise
    """
    if not value:
        return False
    return bool(MD5_PATTERN.match(value.strip()))


def validate_sha1(value):
    """
    Validate SHA-1 hash (40 hexadecimal characters)

    Args:
        value: String to validate

    Returns:
        bool: True if valid SHA-1, False otherwise
    """
    if not value:
        return False
    return bool(SHA1_PATTERN.match(value.strip()))


def validate_sha256(value):
    """
    Validate SHA-256 hash (64 hexadecimal characters)

    Args:
        value: String to validate

    Returns:
        bool: True if valid SHA-256, False otherwise
    """
    if not value:
        return False
    return bool(SHA256_PATTERN.match(value.strip()))


def validate_hash(value):
    """
    Validate any hash type (MD5, SHA1, or SHA256)

    Args:
        value: String to validate

    Returns:
        str: Hash type ('MD5', 'SHA1', 'SHA256') or None if invalid
    """
    value = value.strip() if value else ''

    if validate_md5(value):
        return 'MD5'
    elif validate_sha1(value):
        return 'SHA1'
    elif validate_sha256(value):
        return 'SHA256'

    return None


def validate_ipv4(value):
    """
    Validate IPv4 address

    Args:
        value: String to validate

    Returns:
        bool: True if valid IPv4, False otherwise
    """
    if not value:
        return False

    value = value.strip()

    # Use validators library
    return validators.ipv4(value) is True


def validate_ipv6(value):
    """
    Validate IPv6 address

    Args:
        value: String to validate

    Returns:
        bool: True if valid IPv6, False otherwise
    """
    if not value:
        return False

    value = value.strip()

    # Use validators library
    return validators.ipv6(value) is True


def validate_ip(value):
    """
    Validate any IP address (IPv4 or IPv6)

    Args:
        value: String to validate

    Returns:
        str: IP version ('IPv4', 'IPv6') or None if invalid
    """
    value = value.strip() if value else ''

    if validate_ipv4(value):
        return 'IPv4'
    elif validate_ipv6(value):
        return 'IPv6'

    return None


def validate_email(value):
    """
    Validate email address

    Args:
        value: String to validate

    Returns:
        bool: True if valid email, False otherwise
    """
    if not value:
        return False

    value = value.strip()

    try:
        # Use email-validator library
        email_validate(value, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False


def validate_domain(value):
    """
    Validate domain name

    Args:
        value: String to validate

    Returns:
        bool: True if valid domain, False otherwise
    """
    if not value:
        return False

    value = value.strip().lower()

    # Remove protocol if present
    if value.startswith('http://') or value.startswith('https://'):
        return False  # This is a URL, not a domain

    # Remove trailing dot if present (FQDN)
    if value.endswith('.'):
        value = value[:-1]

    # Use validators library
    return validators.domain(value) is True


def validate_url(value):
    """
    Validate URL

    Args:
        value: String to validate

    Returns:
        bool: True if valid URL, False otherwise
    """
    if not value:
        return False

    value = value.strip()

    # Use validators library
    return validators.url(value) is True


def validate_dns(value):
    """
    Validate DNS hostname (more permissive than domain)

    Args:
        value: String to validate

    Returns:
        bool: True if valid DNS hostname, False otherwise
    """
    if not value:
        return False

    value = value.strip().lower()

    # Remove trailing dot if present
    if value.endswith('.'):
        value = value[:-1]

    # DNS hostname pattern (allows subdomains, numbers, hyphens)
    dns_pattern = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
        r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    )

    return bool(dns_pattern.match(value))


def get_ioc_type(value):
    """
    Auto-detect IOC type from value

    Args:
        value: String to analyze

    Returns:
        str: IOC type name or None if unable to detect
    """
    if not value:
        return None

    value = value.strip()

    # Check hashes (most specific first)
    hash_type = validate_hash(value)
    if hash_type:
        return hash_type

    # Check IP addresses
    ip_type = validate_ip(value)
    if ip_type:
        return ip_type

    # Check URL (before domain, as URLs contain domains)
    if validate_url(value):
        return 'URL'

    # Check email
    if validate_email(value):
        return 'Email'

    # Check domain
    if validate_domain(value):
        return 'Domain'

    # Check DNS hostname
    if validate_dns(value):
        return 'DNS'

    # Unable to determine type
    return None


def sanitize_ioc_value(value, ioc_type=None):
    """
    Sanitize and normalize IOC value

    Args:
        value: IOC value to sanitize
        ioc_type: Optional IOC type (will auto-detect if not provided)

    Returns:
        str: Sanitized IOC value
    """
    if not value:
        return value

    value = value.strip()

    # Auto-detect type if not provided
    if not ioc_type:
        ioc_type = get_ioc_type(value)

    # Normalize based on type
    if ioc_type in ['MD5', 'SHA1', 'SHA256']:
        # Hashes: lowercase
        return value.lower()

    elif ioc_type in ['IPv4', 'IPv6']:
        # IPs: lowercase (for IPv6 hex)
        return value.lower()

    elif ioc_type in ['Email']:
        # Email: lowercase
        return value.lower()

    elif ioc_type in ['Domain', 'DNS']:
        # Domains: lowercase, remove trailing dot
        value = value.lower()
        if value.endswith('.'):
            value = value[:-1]
        return value

    elif ioc_type == 'URL':
        # URLs: lowercase domain part only
        # Keep the path case-sensitive
        return value

    # Default: return as-is with whitespace stripped
    return value


def validate_ioc(value, expected_type=None):
    """
    Validate an IOC value

    Args:
        value: IOC value to validate
        expected_type: Expected IOC type (optional, will auto-detect if not provided)

    Returns:
        tuple: (is_valid: bool, detected_type: str, error_message: str)
    """
    if not value:
        return False, None, "IOC value is required"

    value = value.strip()

    # Auto-detect type
    detected_type = get_ioc_type(value)

    if not detected_type:
        return False, None, "Unable to determine IOC type - invalid format"

    # If expected type is provided, check if it matches
    if expected_type and detected_type != expected_type:
        return False, detected_type, f"Expected {expected_type}, but detected {detected_type}"

    # Validation passed
    return True, detected_type, None


def bulk_parse_iocs(text):
    """
    Parse multiple IOCs from text (one per line or comma/space separated)

    Args:
        text: Text containing multiple IOCs

    Returns:
        list: List of dictionaries with 'value', 'type', and 'original' keys
    """
    if not text:
        return []

    # Split by newlines, commas, or semicolons
    lines = re.split(r'[\n,;]+', text)

    iocs = []
    seen = set()  # Track duplicates

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Try to detect IOC type
        ioc_type = get_ioc_type(line)

        if ioc_type:
            # Sanitize the value
            sanitized = sanitize_ioc_value(line, ioc_type)

            # Check for duplicates
            key = f"{ioc_type}:{sanitized}"
            if key not in seen:
                seen.add(key)
                iocs.append({
                    'value': sanitized,
                    'type': ioc_type,
                    'original': line
                })

    return iocs


# Validation functions mapping for easy lookup
VALIDATORS = {
    'MD5': validate_md5,
    'SHA1': validate_sha1,
    'SHA256': validate_sha256,
    'IPv4': validate_ipv4,
    'IPv6': validate_ipv6,
    'Email': validate_email,
    'Domain': validate_domain,
    'URL': validate_url,
    'DNS': validate_dns,
}
