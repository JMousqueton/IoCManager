#!/usr/bin/env python3
"""
Database Initialization Script
Creates tables, IOC types, default tags, and admin user
"""

import os
import sys
import getpass

# Add parent directory to path to import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models import User, IOCType, Tag


def create_ioc_types():
    """Create default IOC types"""
    ioc_types = [
        {
            'name': 'MD5',
            'description': 'MD5 hash (32 hexadecimal characters)',
            'validation_regex': r'^[a-fA-F0-9]{32}$',
            'icon': 'fa-hashtag'
        },
        {
            'name': 'SHA1',
            'description': 'SHA-1 hash (40 hexadecimal characters)',
            'validation_regex': r'^[a-fA-F0-9]{40}$',
            'icon': 'fa-hashtag'
        },
        {
            'name': 'SHA256',
            'description': 'SHA-256 hash (64 hexadecimal characters)',
            'validation_regex': r'^[a-fA-F0-9]{64}$',
            'icon': 'fa-hashtag'
        },
        {
            'name': 'IPv4',
            'description': 'IPv4 address',
            'validation_regex': r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
            'icon': 'fa-network-wired'
        },
        {
            'name': 'IPv6',
            'description': 'IPv6 address',
            'validation_regex': r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$',
            'icon': 'fa-network-wired'
        },
        {
            'name': 'Email',
            'description': 'Email address',
            'validation_regex': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'icon': 'fa-envelope'
        },
        {
            'name': 'Domain',
            'description': 'Domain name',
            'validation_regex': r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
            'icon': 'fa-globe'
        },
        {
            'name': 'URL',
            'description': 'URL/URI',
            'validation_regex': r'^https?://[^\s]+$',
            'icon': 'fa-link'
        },
        {
            'name': 'DNS',
            'description': 'DNS hostname',
            'validation_regex': r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$',
            'icon': 'fa-server'
        }
    ]

    created_count = 0
    for ioc_type_data in ioc_types:
        existing = IOCType.query.filter_by(name=ioc_type_data['name']).first()
        if not existing:
            ioc_type = IOCType(**ioc_type_data)
            db.session.add(ioc_type)
            created_count += 1
            print(f"  Created IOC type: {ioc_type_data['name']}")
        else:
            print(f"  IOC type already exists: {ioc_type_data['name']}")

    db.session.commit()
    print(f"\n✓ Created {created_count} IOC types")


def create_default_tags():
    """Create default tags for common threat categories"""
    tags = [
        {'name': 'Malware', 'description': 'Malicious software', 'color': '#dc3545'},  # Red
        {'name': 'Phishing', 'description': 'Phishing attack indicators', 'color': '#fd7e14'},  # Orange
        {'name': 'C2', 'description': 'Command and Control infrastructure', 'color': '#6f42c1'},  # Purple
        {'name': 'Exfiltration', 'description': 'Data exfiltration indicators', 'color': '#e83e8c'},  # Pink
        {'name': 'Ransomware', 'description': 'Ransomware related indicators', 'color': '#dc3545'},  # Red
        {'name': 'APT', 'description': 'Advanced Persistent Threat', 'color': '#000000'},  # Black
        {'name': 'Suspicious', 'description': 'Suspicious activity', 'color': '#ffc107'},  # Yellow
        {'name': 'Benign', 'description': 'Confirmed benign', 'color': '#28a745'},  # Green
        {'name': 'Botnet', 'description': 'Botnet infrastructure', 'color': '#6610f2'},  # Indigo
        {'name': 'Spam', 'description': 'Spam related indicators', 'color': '#6c757d'},  # Gray
    ]

    created_count = 0
    for tag_data in tags:
        existing = Tag.query.filter_by(name=tag_data['name']).first()
        if not existing:
            tag = Tag(**tag_data)
            db.session.add(tag)
            created_count += 1
            print(f"  Created tag: {tag_data['name']}")
        else:
            print(f"  Tag already exists: {tag_data['name']}")

    db.session.commit()
    print(f"\n✓ Created {created_count} tags")


def create_admin_user():
    """Create default admin user"""
    print("\n" + "="*60)
    print("CREATE ADMIN USER")
    print("="*60)

    # Check if admin already exists
    admin = User.query.filter_by(role='Admin').first()
    if admin:
        print(f"\n⚠ Admin user already exists: {admin.username}")
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


def main():
    """Main initialization function"""
    print("\n" + "="*60)
    print("IOC MANAGER - DATABASE INITIALIZATION")
    print("="*60)

    # Create app and database tables
    app = create_app()

    with app.app_context():
        print("\n1. Creating database tables...")
        db.create_all()
        print("✓ Database tables created")

        print("\n2. Creating IOC types...")
        create_ioc_types()

        print("\n3. Creating default tags...")
        create_default_tags()

        print("\n4. Creating admin user...")
        create_admin_user()

        print("\n" + "="*60)
        print("✓ DATABASE INITIALIZATION COMPLETE!")
        print("="*60)
        print("\nYou can now run the application with: python run.py")
        print("\n")


if __name__ == '__main__':
    main()
