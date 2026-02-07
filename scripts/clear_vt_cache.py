#!/usr/bin/env python3
"""
Clear VirusTotal cache for a specific hash or all hashes

This allows you to re-enrich IOCs to get updated data (e.g., MITRE ATT&CK info)

Usage:
    # Clear specific hash
    python scripts/clear_vt_cache.py <hash_value>

    # Clear all cache
    python scripts/clear_vt_cache.py --all
"""

import os
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from app.models import VirusTotalCache

app = create_app()

def clear_cache(hash_value=None, clear_all=False):
    """Clear VirusTotal cache"""

    with app.app_context():
        print("=" * 60)
        print("VirusTotal Cache Cleaner")
        print("=" * 60)
        print()

        try:
            if clear_all:
                count = VirusTotalCache.query.delete()
                db.session.commit()
                print(f"✓ Cleared {count} cache entries")

            elif hash_value:
                hash_value = hash_value.lower().strip()
                cache_entry = VirusTotalCache.query.filter_by(hash_value=hash_value).first()

                if cache_entry:
                    db.session.delete(cache_entry)
                    db.session.commit()
                    print(f"✓ Cleared cache for hash: {hash_value}")
                else:
                    print(f"⚠ No cache entry found for hash: {hash_value}")

            else:
                print("Error: Please provide a hash value or use --all flag")
                print()
                print("Usage:")
                print("  python scripts/clear_vt_cache.py <hash_value>")
                print("  python scripts/clear_vt_cache.py --all")
                sys.exit(1)

            print()
            print("Now you can re-enrich the IOC to get updated data!")
            print("=" * 60)

        except Exception as e:
            print(f"✗ Error: {e}")
            print("=" * 60)
            sys.exit(1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python scripts/clear_vt_cache.py <hash_value>")
        print("  python scripts/clear_vt_cache.py --all")
        sys.exit(1)

    if sys.argv[1] == '--all':
        clear_cache(clear_all=True)
    else:
        clear_cache(hash_value=sys.argv[1])
