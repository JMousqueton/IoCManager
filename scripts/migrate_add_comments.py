#!/usr/bin/env python3
"""
One-time migration to add comments table

This creates the comments table for IOC discussions with @mentions and threading support.
Run once after creating the Comment model.

Usage:
    python scripts/migrate_add_comments.py
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
    """Create comments table"""

    with app.app_context():
        print("=" * 60)
        print("IOC Comments Migration")
        print("=" * 60)

        try:
            # Check if table already exists
            with db.engine.connect() as conn:
                result = conn.execute(db.text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='comments'"
                ))
                if result.fetchone():
                    print("✓ comments table already exists")
                    print("=" * 60)
                    return

            # Create table
            print("Creating comments table...")

            with db.engine.connect() as conn:
                conn.execute(db.text("""
                    CREATE TABLE comments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ioc_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        parent_id INTEGER,
                        content TEXT NOT NULL,
                        created_at DATETIME NOT NULL,
                        updated_at DATETIME,
                        FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                        FOREIGN KEY (user_id) REFERENCES users(id),
                        FOREIGN KEY (parent_id) REFERENCES comments(id) ON DELETE CASCADE
                    )
                """))

                # Create indexes
                conn.execute(db.text(
                    "CREATE INDEX ix_comments_ioc_id ON comments (ioc_id)"
                ))
                conn.execute(db.text(
                    "CREATE INDEX ix_comments_parent_id ON comments (parent_id)"
                ))

                conn.commit()

            print("✓ Created comments table")
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
