#!/usr/bin/env python3
"""
Create admin user
"""

import getpass
import sys
from app import create_app, db
from app.models.user import User

def create_admin_user():
    """Create admin user with interactive prompts"""
    print("=== Create Admin User ===\n")

    # Get username
    while True:
        username = input("Username: ").strip()
        if username:
            break
        print("Username cannot be empty. Please try again.")

    # Get email
    while True:
        email = input("Email: ").strip()
        if email and '@' in email:
            break
        print("Please enter a valid email address.")

    # Get password
    while True:
        password = getpass.getpass("Password: ")
        if len(password) < 6:
            print("Password must be at least 6 characters long.")
            continue
        password_confirm = getpass.getpass("Confirm password: ")
        if password == password_confirm:
            break
        print("Passwords do not match. Please try again.")

    # Create the app and user
    app = create_app()

    with app.app_context():
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            print(f"\n⚠ User '{username}' already exists with email: {existing_user.email}")
            response = input("Do you want to update the password? (yes/no): ").strip().lower()
            if response in ['yes', 'y']:
                existing_user.set_password(password)
                existing_user.email = email
                existing_user.role = 'Admin'
                existing_user.is_active = True
                db.session.commit()
                print("\n✓ Admin user updated successfully!")
                print(f"  Username: {existing_user.username}")
                print(f"  Email: {existing_user.email}")
                print(f"  Role: {existing_user.role}")
            else:
                print("Operation cancelled.")
                sys.exit(0)
        else:
            # Check if email already exists
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                print(f"\n✗ Error: Email '{email}' is already registered to user '{existing_email.username}'")
                sys.exit(1)

            # Create new admin user
            admin = User(
                username=username,
                email=email,
                role='Admin',
                is_active=True
            )
            admin.set_password(password)

            db.session.add(admin)
            db.session.commit()

            print("\n✓ Admin user created successfully!")
            print(f"  Username: {admin.username}")
            print(f"  Email: {admin.email}")
            print(f"  Role: {admin.role}")

if __name__ == '__main__':
    try:
        create_admin_user()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)
