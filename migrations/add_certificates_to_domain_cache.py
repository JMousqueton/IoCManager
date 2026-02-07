#!/usr/bin/env python3
"""
Migration script to add certificates column to domain_enrichment_cache table

This adds the certificates field for storing SSL/TLS certificate data from CT logs.
Run once after updating the DomainEnrichmentCache model.

Usage:
    python migrations/add_certificates_to_domain_cache.py
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
    """Add certificates column to domain_enrichment_cache table"""

    with app.app_context():
        print("=" * 60)
        print("Domain Enrichment Cache - Add Certificates Column")
        print("=" * 60)

        try:
            # Check if column already exists
            with db.engine.connect() as conn:
                result = conn.execute(db.text("PRAGMA table_info(domain_enrichment_cache)"))
                columns = [row[1] for row in result]

                if 'certificates' in columns:
                    print("✓ certificates column already exists")
                else:
                    conn.execute(db.text("ALTER TABLE domain_enrichment_cache ADD COLUMN certificates TEXT"))
                    conn.commit()
                    print("✓ Added certificates column")

            print()
            print("Migration completed successfully!")
            print("=" * 60)

        except Exception as e:
            print(f"✗ Migration failed: {e}")
            print("=" * 60)
            sys.exit(1)

if __name__ == '__main__':
    migrate()
