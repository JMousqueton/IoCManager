#!/usr/bin/env python3
"""
Database Migration: Add favicon_path and favicon_sha256 columns to url_enrichment_cache table

This migration adds:
- favicon_path: Local path to downloaded favicon file
- favicon_sha256: SHA256 hash of the favicon file for threat intelligence

Usage:
    python migrations/add_favicon_path_column.py
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
load_dotenv()

from app import create_app, db

app = create_app()


def migrate():
    """Add favicon_path and favicon_sha256 columns to url_enrichment_cache table"""

    with app.app_context():
        print("=" * 70)
        print("DATABASE MIGRATION: Add Favicon Columns")
        print("=" * 70)
        print()

        try:
            # Check if columns already exist
            with db.engine.connect() as conn:
                result = conn.execute(db.text("PRAGMA table_info(url_enrichment_cache)"))
                columns = [row[1] for row in result]

                # Add favicon_path column
                if 'favicon_path' in columns:
                    print("✓ favicon_path column already exists")
                else:
                    print("Adding favicon_path column...")
                    conn.execute(db.text(
                        "ALTER TABLE url_enrichment_cache ADD COLUMN favicon_path VARCHAR(500)"
                    ))
                    conn.commit()
                    print("✓ Successfully added favicon_path column")

                # Add favicon_sha256 column
                if 'favicon_sha256' in columns:
                    print("✓ favicon_sha256 column already exists")
                else:
                    print("Adding favicon_sha256 column...")
                    conn.execute(db.text(
                        "ALTER TABLE url_enrichment_cache ADD COLUMN favicon_sha256 VARCHAR(64)"
                    ))
                    conn.commit()
                    print("✓ Successfully added favicon_sha256 column")

            print()
            print("=" * 70)
            print("Migration completed successfully!")
            print("=" * 70)
            print()

        except Exception as e:
            print(f"✗ Migration failed: {e}")
            print("=" * 70)
            sys.exit(1)


if __name__ == '__main__':
    migrate()
