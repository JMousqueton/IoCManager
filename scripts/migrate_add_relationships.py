#!/usr/bin/env python3
"""
One-time migration to add IOC relationships table

This creates the ioc_relationships table for linking related IOCs.
Run once after creating the IOCRelationship model.

Usage:
    python scripts/migrate_add_relationships.py
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
    """Create ioc_relationships table"""

    with app.app_context():
        print("=" * 60)
        print("IOC Relationships Migration")
        print("=" * 60)

        try:
            # Check if table already exists
            with db.engine.connect() as conn:
                result = conn.execute(db.text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='ioc_relationships'"
                ))
                if result.fetchone():
                    print("✓ ioc_relationships table already exists")
                    print("=" * 60)
                    return

            # Create table
            print("Creating ioc_relationships table...")

            with db.engine.connect() as conn:
                conn.execute(db.text("""
                    CREATE TABLE ioc_relationships (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source_ioc_id INTEGER NOT NULL,
                        target_ioc_id INTEGER NOT NULL,
                        relationship_type VARCHAR(50) NOT NULL,
                        notes TEXT,
                        created_at DATETIME NOT NULL,
                        created_by INTEGER,
                        FOREIGN KEY (source_ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                        FOREIGN KEY (target_ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                        FOREIGN KEY (created_by) REFERENCES users(id)
                    )
                """))

                # Create indexes
                conn.execute(db.text(
                    "CREATE INDEX ix_ioc_relationships_source_ioc_id ON ioc_relationships (source_ioc_id)"
                ))
                conn.execute(db.text(
                    "CREATE INDEX ix_ioc_relationships_target_ioc_id ON ioc_relationships (target_ioc_id)"
                ))
                conn.execute(db.text(
                    "CREATE INDEX ix_ioc_relationships_relationship_type ON ioc_relationships (relationship_type)"
                ))

                conn.commit()

            print("✓ Created ioc_relationships table")
            print("✓ Created indexes")
            print()
            print("Migration completed successfully!")
            print("=" * 60)

        except Exception as e:
            print(f"✗ Migration failed: {e}")
            print("=" * 60)
            sys.exit(1)

if __name__ == '__main__':
    migrate()
