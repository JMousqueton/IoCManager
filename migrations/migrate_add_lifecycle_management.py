#!/usr/bin/env python3
"""
Database migration to add IOC Lifecycle Management features

This migration adds:
1. Reviewer flag to users table
2. Lifecycle status and approval tracking to iocs table
3. Pending notifications queue table

Usage:
    PYTHONPATH=. python3 migrations/migrate_add_lifecycle_management.py
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app import create_app, db
from sqlalchemy import text

def run_migration():
    """Execute the migration"""
    app = create_app()

    with app.app_context():
        print("\n" + "=" * 60)
        print("IOC LIFECYCLE MANAGEMENT MIGRATION")
        print("=" * 60)

        # Step 1: Add is_reviewer column to users table
        print("\n[1/6] Adding is_reviewer column to users table...")
        try:
            db.session.execute(text("""
                ALTER TABLE users ADD COLUMN is_reviewer BOOLEAN NOT NULL DEFAULT 0
            """))
            db.session.commit()
            print("  ✓ Added is_reviewer column")
        except Exception as e:
            if "duplicate column name" in str(e).lower():
                print("  ⚠ Column is_reviewer already exists, skipping")
                db.session.rollback()
            else:
                print(f"  ✗ Error: {e}")
                db.session.rollback()
                raise

        # Step 2: Add lifecycle columns to iocs table
        print("\n[2/6] Adding lifecycle columns to iocs table...")

        columns_to_add = [
            ("status", "VARCHAR(20) NOT NULL DEFAULT 'active'"),
            ("approved_by", "INTEGER NULL"),
            ("approved_at", "DATETIME NULL"),
            ("rejection_reason", "TEXT NULL"),
            ("rejected_at", "DATETIME NULL"),
            ("archived_by", "INTEGER NULL"),
            ("archived_at", "DATETIME NULL"),
            ("archived_reason", "TEXT NULL"),
        ]

        for col_name, col_type in columns_to_add:
            try:
                db.session.execute(text(f"""
                    ALTER TABLE iocs ADD COLUMN {col_name} {col_type}
                """))
                db.session.commit()
                print(f"  ✓ Added {col_name} column")
            except Exception as e:
                if "duplicate column name" in str(e).lower():
                    print(f"  ⚠ Column {col_name} already exists, skipping")
                    db.session.rollback()
                else:
                    print(f"  ✗ Error adding {col_name}: {e}")
                    db.session.rollback()
                    raise

        # Step 3: Create pending_notifications table
        print("\n[3/6] Creating pending_notifications table...")
        try:
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS pending_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    notification_type VARCHAR(50) NOT NULL,
                    ioc_id INTEGER NOT NULL,
                    details TEXT NULL,
                    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (ioc_id) REFERENCES iocs (id) ON DELETE CASCADE
                )
            """))
            db.session.commit()
            print("  ✓ Created pending_notifications table")
        except Exception as e:
            if "already exists" in str(e).lower():
                print("  ⚠ Table pending_notifications already exists, skipping")
                db.session.rollback()
            else:
                print(f"  ✗ Error: {e}")
                db.session.rollback()
                raise

        # Step 4: Migrate existing IOC data
        print("\n[4/6] Migrating existing IOC data...")
        try:
            # Set status='active' for all currently active IOCs
            result = db.session.execute(text("""
                UPDATE iocs
                SET status = 'active'
                WHERE is_active = 1 AND status = 'active'
            """))
            active_count = result.rowcount

            # Set status='archived' for all currently inactive IOCs
            result = db.session.execute(text("""
                UPDATE iocs
                SET status = 'archived'
                WHERE is_active = 0
            """))
            archived_count = result.rowcount

            db.session.commit()
            print(f"  ✓ Migrated {active_count} active IOCs")
            print(f"  ✓ Migrated {archived_count} inactive IOCs to archived status")
        except Exception as e:
            print(f"  ✗ Error migrating data: {e}")
            db.session.rollback()
            raise

        # Step 5: Create indexes
        print("\n[5/6] Creating indexes...")

        indexes = [
            ("idx_iocs_status", "iocs", "status"),
            ("idx_iocs_archived_at", "iocs", "archived_at"),
            ("idx_pending_notifications_user_id", "pending_notifications", "user_id"),
            ("idx_pending_notifications_created_at", "pending_notifications", "created_at"),
        ]

        for idx_name, table_name, column_name in indexes:
            try:
                db.session.execute(text(f"""
                    CREATE INDEX IF NOT EXISTS {idx_name} ON {table_name} ({column_name})
                """))
                db.session.commit()
                print(f"  ✓ Created index {idx_name}")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print(f"  ⚠ Index {idx_name} already exists, skipping")
                    db.session.rollback()
                else:
                    print(f"  ✗ Error creating index {idx_name}: {e}")
                    db.session.rollback()
                    raise

        # Step 6: Create foreign keys (SQLite note: FK constraints enabled at runtime)
        print("\n[6/6] Verifying foreign key constraints...")
        try:
            # Check if foreign keys are enabled
            result = db.session.execute(text("PRAGMA foreign_keys")).fetchone()
            fk_enabled = result[0] if result else 0

            if fk_enabled:
                print("  ✓ Foreign key constraints are enabled")
            else:
                print("  ⚠ Foreign key constraints are disabled (enable in app config)")

            # Note: SQLite foreign keys are defined in CREATE TABLE, not ALTER TABLE
            print("  ✓ Foreign keys defined in table schemas")
        except Exception as e:
            print(f"  ✗ Error checking foreign keys: {e}")

        # Summary
        print("\n" + "=" * 60)
        print("MIGRATION COMPLETED SUCCESSFULLY")
        print("=" * 60)
        print("\nChanges applied:")
        print("  • Added is_reviewer flag to users table")
        print("  • Added 8 lifecycle columns to iocs table")
        print("  • Created pending_notifications table")
        print("  • Migrated existing IOC data (active/archived status)")
        print("  • Created 4 indexes for performance")
        print("\nNext steps:")
        print("  1. Update models: app/models/ioc.py, app/models/user.py")
        print("  2. Create app/models/notification.py")
        print("  3. Add state transition routes to app/routes/ioc.py")
        print("  4. Create NotificationService")
        print("  5. Update UI templates")
        print()

if __name__ == '__main__':
    try:
        run_migration()
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        sys.exit(1)
