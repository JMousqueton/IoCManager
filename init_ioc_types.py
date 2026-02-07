#!/usr/bin/env python3
"""
Initialize IOC Types in the database
"""

from app import create_app, db
from app.models.ioc import IOCType

def init_ioc_types():
    """Initialize common IOC types"""

    print("=== Initialize IOC Types ===\n")

    # Define common IOC types
    ioc_types = [
        {
            'name': 'IPv4',
            'description': 'IPv4 Address (e.g., 192.168.1.1)',
            'validation_regex': r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
            'icon': 'fa-network-wired'
        },
        {
            'name': 'IPv6',
            'description': 'IPv6 Address',
            'validation_regex': r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$',
            'icon': 'fa-network-wired'
        },
        {
            'name': 'Domain',
            'description': 'Domain Name (e.g., example.com)',
            'validation_regex': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
            'icon': 'fa-globe'
        },
        {
            'name': 'URL',
            'description': 'Full URL (e.g., https://example.com/path)',
            'validation_regex': r'^https?://[^\s]+$',
            'icon': 'fa-link'
        },
        {
            'name': 'Email',
            'description': 'Email Address',
            'validation_regex': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'icon': 'fa-envelope'
        },
        {
            'name': 'MD5',
            'description': 'MD5 Hash (32 characters)',
            'validation_regex': r'^[a-fA-F0-9]{32}$',
            'icon': 'fa-fingerprint'
        },
        {
            'name': 'SHA1',
            'description': 'SHA1 Hash (40 characters)',
            'validation_regex': r'^[a-fA-F0-9]{40}$',
            'icon': 'fa-fingerprint'
        },
        {
            'name': 'SHA256',
            'description': 'SHA256 Hash (64 characters)',
            'validation_regex': r'^[a-fA-F0-9]{64}$',
            'icon': 'fa-fingerprint'
        },
        {
            'name': 'SHA512',
            'description': 'SHA512 Hash (128 characters)',
            'validation_regex': r'^[a-fA-F0-9]{128}$',
            'icon': 'fa-fingerprint'
        },
        {
            'name': 'SSDEEP',
            'description': 'SSDEEP Fuzzy Hash',
            'validation_regex': None,
            'icon': 'fa-fingerprint'
        },
        {
            'name': 'Filename',
            'description': 'Malicious Filename',
            'validation_regex': None,
            'icon': 'fa-file'
        },
        {
            'name': 'File Path',
            'description': 'File Path or Directory',
            'validation_regex': None,
            'icon': 'fa-folder'
        },
        {
            'name': 'Registry Key',
            'description': 'Windows Registry Key',
            'validation_regex': r'^(HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\.*',
            'icon': 'fa-key'
        },
        {
            'name': 'Mutex',
            'description': 'Mutex Name',
            'validation_regex': None,
            'icon': 'fa-lock'
        },
        {
            'name': 'CVE',
            'description': 'CVE Identifier (e.g., CVE-2021-12345)',
            'validation_regex': r'^CVE-\d{4}-\d{4,}$',
            'icon': 'fa-bug'
        },
        {
            'name': 'User-Agent',
            'description': 'HTTP User-Agent String',
            'validation_regex': None,
            'icon': 'fa-user-secret'
        },
        {
            'name': 'Certificate',
            'description': 'SSL/TLS Certificate Hash or Serial',
            'validation_regex': None,
            'icon': 'fa-certificate'
        },
        {
            'name': 'CIDR',
            'description': 'CIDR IP Range (e.g., 192.168.1.0/24)',
            'validation_regex': r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$',
            'icon': 'fa-network-wired'
        },
        {
            'name': 'ASN',
            'description': 'Autonomous System Number (e.g., AS15169)',
            'validation_regex': r'^AS\d+$',
            'icon': 'fa-server'
        },
        {
            'name': 'Bitcoin Address',
            'description': 'Bitcoin Wallet Address',
            'validation_regex': r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$|^bc1[a-z0-9]{39,59}$',
            'icon': 'fa-bitcoin-sign'
        },
        {
            'name': 'Other',
            'description': 'Other IOC Type',
            'validation_regex': None,
            'icon': 'fa-circle-question'
        }
    ]

    app = create_app()

    with app.app_context():
        print(f"Found {IOCType.query.count()} existing IOC types")

        added = 0
        skipped = 0

        for ioc_type_data in ioc_types:
            # Check if type already exists
            existing = IOCType.query.filter_by(name=ioc_type_data['name']).first()

            if existing:
                print(f"  ⚠ Skipping '{ioc_type_data['name']}' (already exists)")
                skipped += 1
            else:
                ioc_type = IOCType(
                    name=ioc_type_data['name'],
                    description=ioc_type_data['description'],
                    validation_regex=ioc_type_data['validation_regex'],
                    icon=ioc_type_data['icon']
                )
                db.session.add(ioc_type)
                print(f"  ✓ Added '{ioc_type_data['name']}'")
                added += 1

        db.session.commit()

        print(f"\n✓ Initialization complete!")
        print(f"  Added: {added}")
        print(f"  Skipped: {skipped}")
        print(f"  Total: {IOCType.query.count()}")

if __name__ == '__main__':
    try:
        init_ioc_types()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
