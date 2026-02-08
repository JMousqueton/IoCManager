#!/usr/bin/env python3
"""
Database Migration: Add MFA Support
Adds MFA-related columns to users table and creates MFA verification attempts table.
"""

import os
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from sqlalchemy import text

app = create_app()

def migrate():
    """Run migration"""
    print("=" * 60)
    print("DATABASE MIGRATION: Add MFA Support")
    print("=" * 60)

    with app.app_context():
        try:
            # Check if columns already exist
            with db.engine.connect() as conn:
                result = conn.execute(text("PRAGMA table_info(users)"))
                columns = [row[1] for row in result]

                if 'mfa_enabled' in columns:
                    print("✓ MFA columns already exist, skipping.")
                    return

                # Add MFA columns to users table
                print("Adding MFA columns to users table...")
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0"))
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(255)"))
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_backup_codes TEXT"))
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_backup_codes_used TEXT"))
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_enabled_at DATETIME"))
                conn.execute(text("ALTER TABLE users ADD COLUMN mfa_last_used DATETIME"))
                conn.execute(text("CREATE INDEX idx_users_mfa_enabled ON users(mfa_enabled)"))
                conn.commit()
                print("✓ MFA columns added successfully")

                # Create MFA verification attempts table
                print("Creating MFA verification attempts table...")
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS mfa_verification_attempts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        ip_address VARCHAR(45) NOT NULL,
                        success BOOLEAN NOT NULL DEFAULT 0,
                        timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        attempt_type VARCHAR(20) NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users(id)
                    )
                """))
                conn.execute(text("CREATE INDEX idx_mfa_attempts_user ON mfa_verification_attempts(user_id)"))
                conn.execute(text("CREATE INDEX idx_mfa_attempts_timestamp ON mfa_verification_attempts(timestamp)"))
                conn.commit()
                print("✓ MFA verification attempts table created successfully")

            print("=" * 60)
            print("✓ MIGRATION COMPLETED SUCCESSFULLY")
            print("=" * 60)
            print("\nMFA support has been added to the database.")
            print("Users can now enable MFA from their profile page.")

        except Exception as e:
            print(f"\n✗ Migration failed: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == '__main__':
    migrate()
