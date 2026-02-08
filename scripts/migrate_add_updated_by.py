#!/usr/bin/env python3
"""
One-time migration to add updated_by field to IOC table

This adds the updated_by column to the existing database.
Run once after updating the IOC model.

Usage:
    python scripts/migrate_add_updated_by.py
"""

import os
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
load_dotenv()

from app import create_app, db

app = create_app()

def migrate():
    """Add updated_by column to IOC table"""

    with app.app_context():
        print("=" * 60)
        print("IOC Updated By Migration")
        print("=" * 60)

        try:
            # Check if column already exists
            with db.engine.connect() as conn:
                result = conn.execute(db.text("PRAGMA table_info(iocs)"))
                columns = [row[1] for row in result]

                if 'updated_by' in columns:
                    print("✓ updated_by column already exists")
                else:
                    conn.execute(db.text("ALTER TABLE iocs ADD COLUMN updated_by INTEGER REFERENCES users(id)"))
                    conn.commit()
                    print("✓ Added updated_by column")

            print()
            print("Migration completed successfully!")
            print("=" * 60)

        except Exception as e:
            print(f"✗ Migration failed: {e}")
            print("=" * 60)
            sys.exit(1)

if __name__ == '__main__':
    migrate()
