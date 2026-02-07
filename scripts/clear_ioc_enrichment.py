#!/usr/bin/env python3
"""
Clear enrichment data from IOCs

This removes the stored enrichment data from IOCs so they can be re-enriched
with fresh data from external services.

Usage:
    # Clear specific IOC by ID
    python scripts/clear_ioc_enrichment.py <ioc_id>

    # Clear all IOCs enrichment
    python scripts/clear_ioc_enrichment.py --all

    # Clear all hash-type IOCs (SHA256, MD5, SHA1)
    python scripts/clear_ioc_enrichment.py --hash-types
"""

import os
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from app.models import IOC

app = create_app()

def clear_enrichment(ioc_id=None, clear_all=False, hash_types_only=False):
    """Clear IOC enrichment data"""

    with app.app_context():
        print("=" * 60)
        print("IOC Enrichment Data Cleaner")
        print("=" * 60)
        print()

        try:
            if clear_all:
                iocs = IOC.query.all()
                count = 0
                for ioc in iocs:
                    if ioc.enrichment_data:
                        ioc.enrichment_data = None
                        count += 1
                db.session.commit()
                print(f"✓ Cleared enrichment data from {count} IOC(s)")

            elif hash_types_only:
                iocs = IOC.query.join(IOC.ioc_type).filter(
                    db.or_(
                        IOC.ioc_type.has(name='SHA256'),
                        IOC.ioc_type.has(name='MD5'),
                        IOC.ioc_type.has(name='SHA1')
                    )
                ).all()
                count = 0
                for ioc in iocs:
                    if ioc.enrichment_data:
                        ioc.enrichment_data = None
                        count += 1
                db.session.commit()
                print(f"✓ Cleared enrichment data from {count} hash-type IOC(s)")

            elif ioc_id:
                ioc = IOC.query.get(ioc_id)
                if ioc:
                    if ioc.enrichment_data:
                        ioc.enrichment_data = None
                        db.session.commit()
                        print(f"✓ Cleared enrichment data from IOC #{ioc_id}")
                    else:
                        print(f"⚠ IOC #{ioc_id} has no enrichment data")
                else:
                    print(f"✗ IOC #{ioc_id} not found")
                    sys.exit(1)

            else:
                print("Error: Please provide an IOC ID or use a flag")
                print()
                print("Usage:")
                print("  python scripts/clear_ioc_enrichment.py <ioc_id>")
                print("  python scripts/clear_ioc_enrichment.py --all")
                print("  python scripts/clear_ioc_enrichment.py --hash-types")
                sys.exit(1)

            print()
            print("Now click 'Enrich IOC' button on the IOC detail page to get fresh data!")
            print("=" * 60)

        except Exception as e:
            print(f"✗ Error: {e}")
            import traceback
            traceback.print_exc()
            print("=" * 60)
            sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scripts/clear_ioc_enrichment.py <ioc_id>")
        print("  python scripts/clear_ioc_enrichment.py --all")
        print("  python scripts/clear_ioc_enrichment.py --hash-types")
        sys.exit(1)

    arg = sys.argv[1]
    if arg == '--all':
        clear_enrichment(clear_all=True)
    elif arg == '--hash-types':
        clear_enrichment(hash_types_only=True)
    else:
        try:
            ioc_id = int(arg)
            clear_enrichment(ioc_id=ioc_id)
        except ValueError:
            print(f"Error: Invalid IOC ID '{arg}'")
            print("Must be a number or --all or --hash-types")
            sys.exit(1)
