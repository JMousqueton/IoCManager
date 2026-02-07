#!/usr/bin/env python3
"""
Migration script to add url_enrichment_cache table

This adds the table for storing URL enrichment data (headers, server info, SSL certificates).
Run once after updating the URLEnrichmentCache model.

Usage:
    python migrations/add_url_enrichment_cache.py
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
    """Add url_enrichment_cache table"""

    with app.app_context():
        print("=" * 60)
        print("URL Enrichment Cache - Create Table")
        print("=" * 60)

        try:
            # Check if table already exists
            with db.engine.connect() as conn:
                result = conn.execute(db.text("SELECT name FROM sqlite_master WHERE type='table' AND name='url_enrichment_cache'"))
                table_exists = result.fetchone() is not None

                if table_exists:
                    print("✓ url_enrichment_cache table already exists")
                else:
                    # Create the table
                    conn.execute(db.text("""
                        CREATE TABLE url_enrichment_cache (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            url VARCHAR(2048) NOT NULL UNIQUE,
                            status_code INTEGER,
                            server VARCHAR(500),
                            headers TEXT,
                            technologies TEXT,
                            security_headers TEXT,
                            redirect_url VARCHAR(2048),
                            response_time FLOAT,
                            content_type VARCHAR(200),
                            favicon_url VARCHAR(2048),
                            ssl_certificate TEXT,
                            cached_at DATETIME,
                            expires_at DATETIME NOT NULL
                        )
                    """))

                    # Create indexes
                    conn.execute(db.text("CREATE INDEX ix_url_enrichment_cache_url ON url_enrichment_cache (url)"))
                    conn.execute(db.text("CREATE INDEX ix_url_enrichment_cache_expires_at ON url_enrichment_cache (expires_at)"))

                    conn.commit()
                    print("✓ Created url_enrichment_cache table with indexes")

            print()
            print("Migration completed successfully!")
            print("=" * 60)

        except Exception as e:
            print(f"✗ Migration failed: {e}")
            print("=" * 60)
            sys.exit(1)

if __name__ == '__main__':
    migrate()
