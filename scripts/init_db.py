#!/usr/bin/env python3
"""
Database Initialization Script

This script initializes the IOC Manager database with:
- All database tables (including cache tables)
- Comprehensive IOC types (20+ types)
- Default tags
- Admin user (interactive or default)
- Sample data (optional)

Usage:
    python scripts/init_db.py                    # Standard initialization (interactive)
    python scripts/init_db.py --auto             # Non-interactive with defaults
    python scripts/init_db.py --with-samples     # Include sample data
    python scripts/init_db.py --reset            # Reset database (drop all tables first)
"""

import os
import sys
import getpass
import argparse
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create Flask app context
from app import create_app, db
from app.models import (
    User, IOC, IOCType, Tag, IOCTag, OperatingSystem,
    PendingNotification,
    VirusTotalCache, ASLookupCache, URLScanCache,
    DomainEnrichmentCache, URLEnrichmentCache,
    AuditLog, Session
)
from datetime import datetime


app = create_app()


def drop_all_tables():
    """Drop all database tables"""
    print("⚠️  Dropping all tables...")
    with app.app_context():
        db.drop_all()
        print("✓ All tables dropped")


def create_all_tables():
    """Create all database tables"""
    print("\nCreating database tables...")
    with app.app_context():
        db.create_all()
        print("✓ All tables created successfully")
        print("  - Users")
        print("  - IOC Types")
        print("  - IOCs (with lifecycle status: draft | review | active | archived)")
        print("  - Tags")
        print("  - Operating Systems")
        print("  - Pending Notifications (lifecycle digest queue)")
        print("  - Cache tables (VirusTotal, URLScan, Domain Enrichment, URL Enrichment, AS Lookup)")
        print("  - Audit Logs")
        print("  - Sessions")


def create_ioc_types():
    """Create comprehensive IOC types (combined from both scripts)"""
    print("\nCreating IOC types...")

    ioc_types = [
        # Network Indicators
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
            'name': 'CIDR',
            'description': 'CIDR IP Range (e.g., 192.168.1.0/24)',
            'validation_regex': r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([0-9]|[1-2][0-9]|3[0-2])$',
            'icon': 'fa-network-wired'
        },
        {
            'name': 'Domain',
            'description': 'Domain Name (e.g., example.com)',
            'validation_regex': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
            'icon': 'fa-globe'
        },
        {
            'name': 'DNS',
            'description': 'DNS hostname',
            'validation_regex': r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$',
            'icon': 'fa-server'
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
            'name': 'ASN',
            'description': 'Autonomous System Number (e.g., AS15169)',
            'validation_regex': r'^AS\d+$',
            'icon': 'fa-server'
        },

        # File Hashes
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

        # File & System Artifacts
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

        # Vulnerabilities & Security
        {
            'name': 'CVE',
            'description': 'CVE Identifier (e.g., CVE-2021-12345)',
            'validation_regex': r'^CVE-\d{4}-\d{4,}$',
            'icon': 'fa-bug'
        },
        {
            'name': 'Certificate',
            'description': 'SSL/TLS Certificate Hash or Serial',
            'validation_regex': None,
            'icon': 'fa-certificate'
        },

        # Other Indicators
        {
            'name': 'User-Agent',
            'description': 'HTTP User-Agent String',
            'validation_regex': None,
            'icon': 'fa-user-secret'
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

    with app.app_context():
        created_count = 0
        skipped_count = 0

        for ioc_type_data in ioc_types:
            existing = IOCType.query.filter_by(name=ioc_type_data['name']).first()
            if not existing:
                ioc_type = IOCType(**ioc_type_data)
                db.session.add(ioc_type)
                created_count += 1
                print(f"  ✓ Created IOC type: {ioc_type_data['name']}")
            else:
                skipped_count += 1
                print(f"  - IOC type already exists: {ioc_type_data['name']}")

        db.session.commit()
        print(f"\n✓ IOC Types Summary:")
        print(f"  Created: {created_count}")
        print(f"  Skipped: {skipped_count}")
        print(f"  Total: {IOCType.query.count()}")


def create_default_tags():
    """Create default tags for common threat categories"""
    print("\nCreating default tags...")

    tags = [
        {'name': 'Malware', 'description': 'Malicious software', 'color': '#dc3545'},
        {'name': 'Phishing', 'description': 'Phishing attack indicators', 'color': '#fd7e14'},
        {'name': 'C2', 'description': 'Command and Control infrastructure', 'color': '#6f42c1'},
        {'name': 'Exfiltration', 'description': 'Data exfiltration indicators', 'color': '#e83e8c'},
        {'name': 'Ransomware', 'description': 'Ransomware related indicators', 'color': '#dc3545'},
        {'name': 'APT', 'description': 'Advanced Persistent Threat', 'color': '#000000'},
        {'name': 'Suspicious', 'description': 'Suspicious activity', 'color': '#ffc107'},
        {'name': 'Benign', 'description': 'Confirmed benign', 'color': '#28a745'},
        {'name': 'Botnet', 'description': 'Botnet infrastructure', 'color': '#6610f2'},
        {'name': 'Spam', 'description': 'Spam related indicators', 'color': '#6c757d'},
    ]

    with app.app_context():
        created_count = 0
        for tag_data in tags:
            existing = Tag.query.filter_by(name=tag_data['name']).first()
            if not existing:
                tag = Tag(**tag_data)
                db.session.add(tag)
                created_count += 1
                print(f"  ✓ Created tag: {tag_data['name']}")
            else:
                print(f"  - Tag already exists: {tag_data['name']}")

        db.session.commit()
        print(f"\n✓ Created {created_count} tags")


def create_operating_systems():
    """Create default operating systems for hash IOCs"""
    print("\nCreating operating systems...")

    operating_systems = [
        {'name': 'Exe64', 'icon': 'fa-brands fa-windows', 'description': 'Windows 64-bit executable'},
        {'name': 'Exe32', 'icon': 'fa-brands fa-windows', 'description': 'Windows 32-bit executable'},
        {'name': 'ELF', 'icon': 'fa-brands fa-linux', 'description': 'Linux ELF binary'},
        {'name': 'Mach-O', 'icon': 'fa-brands fa-apple', 'description': 'macOS Mach-O binary'},
        {'name': 'APK', 'icon': 'fa-brands fa-android', 'description': 'Android APK package'},
        {'name': 'DMG', 'icon': 'fa-brands fa-apple', 'description': 'macOS Disk Image'},
        {'name': 'JAR', 'icon': 'fa-brands fa-java', 'description': 'Java Archive'},
        {'name': 'DLL', 'icon': 'fa-brands fa-windows', 'description': 'Windows Dynamic Link Library'},
        {'name': 'Script', 'icon': 'fa-solid fa-file-code', 'description': 'Script file (Python, Shell, PowerShell, etc.)'},
        {'name': 'Document', 'icon': 'fa-solid fa-file-pdf', 'description': 'Document (PDF, Office, etc.)'},
        {'name': 'Other', 'icon': 'fa-solid fa-question', 'description': 'Other or unknown file type'}
    ]

    with app.app_context():
        created_count = 0
        for os_data in operating_systems:
            existing = OperatingSystem.query.filter_by(name=os_data['name']).first()
            if not existing:
                os_entry = OperatingSystem(**os_data)
                db.session.add(os_entry)
                created_count += 1
                print(f"  ✓ Created operating system: {os_data['name']}")
            else:
                print(f"  - Operating system already exists: {os_data['name']}")

        db.session.commit()
        print(f"\n✓ Created {created_count} operating systems")


def create_admin_user_interactive():
    """Create admin user with interactive prompts"""
    print("\n" + "=" * 60)
    print("CREATE ADMIN USER")
    print("=" * 60)

    with app.app_context():
        # Check if admin already exists
        admin = User.query.filter_by(role='Admin').first()
        if admin:
            print(f"\n⚠  Admin user already exists: {admin.username}")
            response = input("Do you want to create another admin user? (y/N): ").strip().lower()
            if response != 'y':
                return

        # Get admin credentials
        username = input("\nEnter admin username (default: admin): ").strip() or 'admin'

        # Check if username exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"✗ User '{username}' already exists!")
            return

        email = input("Enter admin email: ").strip()
        while not email or '@' not in email:
            print("✗ Invalid email address")
            email = input("Enter admin email: ").strip()

        # Get password
        password = getpass.getpass("Enter admin password: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            print("✗ Passwords do not match!")
            return

        if len(password) < 8:
            print("✗ Password must be at least 8 characters long!")
            return

        # Create admin user
        admin = User(
            username=username,
            email=email,
            role='Admin',
            is_active=True
        )
        admin.set_password(password)

        db.session.add(admin)
        db.session.commit()

        print(f"\n✓ Admin user created successfully!")
        print(f"  Username: {username}")
        print(f"  Email: {email}")
        print(f"  Role: Admin")


def create_admin_user_auto():
    """Create default admin user automatically"""
    print("\nCreating default admin user...")

    with app.app_context():
        admin_email = 'admin@example.com'
        admin_username = 'admin'

        existing_admin = User.query.filter_by(email=admin_email).first()

        if not existing_admin:
            admin = User(
                username=admin_username,
                email=admin_email,
                role='Admin',
                is_active=True
            )
            admin.set_password('admin')  # Change this in production!
            db.session.add(admin)
            db.session.commit()

            print(f"  ✓ Created admin user")
            print(f"    Email: {admin_email}")
            print(f"    Username: {admin_username}")
            print(f"    Password: admin")
            print(f"\n  ⚠️  WARNING: Change the admin password immediately!")
        else:
            print(f"  - Admin user already exists: {admin_email}")


def create_sample_data():
    """Create sample IOCs and tags for testing"""
    print("\nCreating sample data...")

    with app.app_context():
        # Get admin user
        admin = User.query.filter_by(role='Admin').first()
        if not admin:
            print("  ✗ Admin user not found, skipping sample IOCs")
            return

        # Sample IOCs
        sample_iocs = [
            {
                'type': 'IPv4',
                'value': '192.0.2.1',
                'description': 'Sample malicious IP address (RFC 5737 TEST-NET-1)',
                'severity': 'High',
                'tlp': 'RED',
                'tags': ['Malware', 'C2']
            },
            {
                'type': 'Domain',
                'value': 'malicious.example.com',
                'description': 'Sample malicious domain',
                'severity': 'High',
                'tlp': 'AMBER',
                'tags': ['Phishing']
            },
            {
                'type': 'URL',
                'value': 'https://malicious.example.com/phishing',
                'description': 'Sample phishing URL',
                'severity': 'Medium',
                'tlp': 'AMBER',
                'tags': ['Phishing']
            },
            {
                'type': 'SHA256',
                'value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'description': 'Sample malicious file hash (empty file SHA256)',
                'severity': 'High',
                'tlp': 'RED',
                'tags': ['Malware', 'Ransomware']
            },
            {
                'type': 'Email',
                'value': 'phishing@malicious.example.com',
                'description': 'Sample phishing email address',
                'severity': 'Medium',
                'tlp': 'AMBER',
                'tags': ['Phishing']
            },
        ]

        created_count = 0
        for ioc_data in sample_iocs:
            # Check if IOC already exists
            ioc_type = IOCType.query.filter_by(name=ioc_data['type']).first()
            if not ioc_type:
                print(f"  ✗ IOC type not found: {ioc_data['type']}")
                continue

            existing_ioc = IOC.query.filter_by(
                value=ioc_data['value'],
                ioc_type_id=ioc_type.id
            ).first()

            if not existing_ioc:
                ioc = IOC(
                    value=ioc_data['value'],
                    ioc_type_id=ioc_type.id,
                    description=ioc_data['description'],
                    severity=ioc_data['severity'],
                    tlp=ioc_data['tlp'],
                    is_active=True,
                    status='active',  # Sample data is created directly as active
                    created_by=admin.id,
                    created_at=datetime.utcnow()
                )
                db.session.add(ioc)
                db.session.flush()  # Get IOC ID

                # Add tags
                for tag_name in ioc_data.get('tags', []):
                    tag = Tag.query.filter_by(name=tag_name).first()
                    if tag:
                        ioc_tag = IOCTag(ioc_id=ioc.id, tag_id=tag.id)
                        db.session.add(ioc_tag)

                created_count += 1
                print(f"  ✓ Created sample IOC: {ioc_data['type']} - {ioc_data['value'][:50]}")
            else:
                print(f"  - IOC already exists: {ioc_data['type']} - {ioc_data['value'][:50]}")

        if created_count > 0:
            db.session.commit()
            print(f"\n✓ Created {created_count} sample IOCs")
        else:
            print("\n✓ All sample IOCs already exist")


def show_database_info():
    """Show database information"""
    print("\n" + "=" * 60)
    print("DATABASE INFORMATION")
    print("=" * 60)

    with app.app_context():
        # Count records
        user_count = User.query.count()
        ioc_count = IOC.query.count()
        tag_count = Tag.query.count()
        ioc_type_count = IOCType.query.count()
        os_count = OperatingSystem.query.count()
        notif_count = PendingNotification.query.count()

        # Lifecycle status breakdown
        draft_count = IOC.query.filter_by(status='draft').count()
        review_count = IOC.query.filter_by(status='review').count()
        active_count = IOC.query.filter_by(status='active').count()
        archived_count = IOC.query.filter_by(status='archived').count()

        print(f"\nRecords:")
        print(f"  Users: {user_count}")
        print(f"  IOC Types: {ioc_type_count}")
        print(f"  IOCs: {ioc_count}")
        print(f"    - Draft:    {draft_count}")
        print(f"    - Review:   {review_count}")
        print(f"    - Active:   {active_count}")
        print(f"    - Archived: {archived_count}")
        print(f"  Tags: {tag_count}")
        print(f"  Operating Systems: {os_count}")
        print(f"  Pending Notifications: {notif_count}")

        # List users
        if user_count > 0:
            print("\nUsers:")
            users = User.query.all()
            for user in users:
                print(f"  - {user.username} ({user.email}) - Role: {user.role}")

        print("=" * 60)


def main():
    """Main initialization function"""
    parser = argparse.ArgumentParser(description='Initialize IOC Manager database')
    parser.add_argument('--reset', action='store_true', help='Reset database (drop all tables first)')
    parser.add_argument('--auto', action='store_true', help='Non-interactive mode with default admin')
    parser.add_argument('--with-samples', action='store_true', help='Create sample data')
    parser.add_argument('--skip-admin', action='store_true', help='Skip admin user creation')

    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("IOC MANAGER - DATABASE INITIALIZATION")
    print("=" * 60)

    try:
        # Reset database if requested
        if args.reset:
            print("\n⚠️  WARNING: This will delete all existing data!")
            if not args.auto:
                response = input("Are you sure you want to reset the database? (yes/no): ")
                if response.lower() != 'yes':
                    print("Reset cancelled.")
                    return
            drop_all_tables()

        # Create tables
        create_all_tables()

        # Create default data
        create_ioc_types()
        create_default_tags()
        create_operating_systems()

        # Create admin user
        if not args.skip_admin:
            if args.auto:
                create_admin_user_auto()
            else:
                create_admin_user_interactive()

        # Create sample data if requested
        if args.with_samples:
            create_sample_data()

        # Show database info
        show_database_info()

        print("\n✓ DATABASE INITIALIZATION COMPLETED SUCCESSFULLY!")
        print("\nYou can now run the application with: python run.py")

        if args.auto and not args.skip_admin:
            print("\nDefault login credentials:")
            print("  Email: admin@example.com")
            print("  Password: admin")
            print("\n⚠️  IMPORTANT: Change the admin password after first login!")

        print()

    except Exception as e:
        print(f"\n✗ Error during initialization: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
