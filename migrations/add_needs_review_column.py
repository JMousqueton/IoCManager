#!/usr/bin/env python3
"""
Migration script to add needs_review column to iocs table
"""

import sys
import os

# Add parent directory to path to import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db

def migrate():
    """Add needs_review column to iocs table"""
    app = create_app()

    with app.app_context():
        try:
            # Check if column already exists
            inspector = db.inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('iocs')]

            if 'needs_review' in columns:
                print("✓ Column 'needs_review' already exists in iocs table")
                return

            print("Adding 'needs_review' column to iocs table...")

            # Add the column
            with db.engine.connect() as conn:
                conn.execute(db.text(
                    "ALTER TABLE iocs ADD COLUMN needs_review BOOLEAN NOT NULL DEFAULT 0"
                ))
                conn.commit()

            print("✓ Successfully added 'needs_review' column")
            print("✓ Migration completed successfully!")

        except Exception as e:
            print(f"✗ Error during migration: {e}")
            raise

if __name__ == '__main__':
    migrate()
