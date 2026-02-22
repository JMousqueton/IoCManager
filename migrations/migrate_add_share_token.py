#!/usr/bin/env python3
"""
Migration: Add share_token column to iocs table

Adds a unique UUID token per IOC used for public share links (/shared_ioc/<token>).
Existing IOCs get a newly generated UUID assigned.

Usage:
    python scripts/migrate_add_share_token.py
"""

import os
import sys
import uuid

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from sqlalchemy import text


def migrate():
    app = create_app()

    with app.app_context():
        with db.engine.connect() as conn:
            # Check if column already exists
            result = conn.execute(text("PRAGMA table_info(iocs)"))
            columns = [row[1] for row in result]

            if 'share_token' in columns:
                print("✓ share_token column already exists — skipping.")
                return

            print("Adding share_token column to iocs table...")
            # SQLite doesn't support UNIQUE on ALTER TABLE ADD COLUMN,
            # so add the column first, then create the index separately.
            conn.execute(text(
                "ALTER TABLE iocs ADD COLUMN share_token VARCHAR(36)"
            ))
            conn.commit()
            print("✓ Column added.")

        # Populate existing rows with unique UUIDs
        from app.models.ioc import IOC
        iocs = IOC.query.filter(IOC.share_token.is_(None)).all()
        print(f"Generating tokens for {len(iocs)} existing IOC(s)...")

        for ioc in iocs:
            ioc.share_token = str(uuid.uuid4())

        db.session.commit()
        print(f"✓ Tokens generated for {len(iocs)} IOC(s).")

        # Create unique index after values are populated
        with db.engine.connect() as conn:
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_iocs_share_token ON iocs (share_token)"
            ))
            conn.commit()
        print("✓ Unique index created.")
        print("\nMigration complete.")


if __name__ == '__main__':
    migrate()
