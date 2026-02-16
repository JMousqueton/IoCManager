#!/usr/bin/env python3
"""
Migration: Add Operating System support for hash IOCs
- Creates operating_systems table
- Adds operating_system_id foreign key to iocs table
- Seeds default operating systems
"""

from app import create_app, db
from sqlalchemy import text

def migrate():
    app = create_app()
    with app.app_context():
        try:
            print("Starting Operating System migration...")

            # Check if operating_systems table exists
            result = db.session.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='operating_systems'"
            )).fetchone()

            if not result:
                print("Creating operating_systems table...")
                db.session.execute(text("""
                    CREATE TABLE operating_systems (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(50) NOT NULL UNIQUE,
                        icon VARCHAR(50),
                        description TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """))
                print("✓ operating_systems table created")

                # Insert default operating systems
                print("Inserting default operating systems...")
                default_os = [
                    ('Exe64', 'fa-brands fa-windows', 'Windows 64-bit executable'),
                    ('Exe32', 'fa-brands fa-windows', 'Windows 32-bit executable'),
                    ('ELF', 'fa-brands fa-linux', 'Linux ELF binary'),
                    ('Mach-O', 'fa-brands fa-apple', 'macOS Mach-O binary'),
                    ('APK', 'fa-brands fa-android', 'Android APK package'),
                    ('DMG', 'fa-brands fa-apple', 'macOS Disk Image'),
                    ('JAR', 'fa-brands fa-java', 'Java Archive'),
                    ('DLL', 'fa-brands fa-windows', 'Windows Dynamic Link Library'),
                    ('Script', 'fa-solid fa-file-code', 'Script file (Python, Shell, PowerShell, etc.)'),
                    ('Document', 'fa-solid fa-file-pdf', 'Document (PDF, Office, etc.)'),
                    ('Other', 'fa-solid fa-question', 'Other or unknown file type')
                ]

                for name, icon, desc in default_os:
                    db.session.execute(text(
                        "INSERT INTO operating_systems (name, icon, description) VALUES (:name, :icon, :desc)"
                    ), {'name': name, 'icon': icon, 'desc': desc})
                print(f"✓ Inserted {len(default_os)} default operating systems")
            else:
                print("operating_systems table already exists, skipping creation")

            # Check if operating_system_id column exists in iocs table
            result = db.session.execute(text(
                "SELECT * FROM pragma_table_info('iocs') WHERE name='operating_system_id'"
            )).fetchone()

            if not result:
                print("Adding operating_system_id column to iocs table...")
                db.session.execute(text(
                    "ALTER TABLE iocs ADD COLUMN operating_system_id INTEGER REFERENCES operating_systems(id)"
                ))
                print("✓ operating_system_id column added")
            else:
                print("operating_system_id column already exists, skipping")

            db.session.commit()
            print("\n✓ Operating System migration completed successfully!")

        except Exception as e:
            print(f"\n✗ Migration failed: {e}")
            db.session.rollback()
            raise

if __name__ == '__main__':
    migrate()
