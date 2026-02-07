#!/usr/bin/env python3
"""
Clear URL Enrichment Cache

This script clears all entries from the url_enrichment_cache table.
Useful when you want to force re-enrichment of URLs.

Usage:
    python scripts/clear_url_cache.py                    # Clear all entries
    python scripts/clear_url_cache.py <url>              # Clear specific URL
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create Flask app context
from app import create_app, db
from app.models import URLEnrichmentCache

app = create_app()

def clear_cache(url=None):
    """Clear URL enrichment cache"""

    with app.app_context():
        print("=" * 60)
        print("URL Enrichment Cache - Clear")
        print("=" * 60)
        print()

        try:
            if url:
                # Clear specific URL
                print(f"Clearing cache for: {url}")
                cache_entry = URLEnrichmentCache.query.filter_by(url=url).first()

                if cache_entry:
                    db.session.delete(cache_entry)
                    db.session.commit()
                    print(f"✓ Cleared cache for: {url}")
                else:
                    print(f"✗ No cache entry found for: {url}")
            else:
                # Clear all cache
                count = URLEnrichmentCache.query.count()

                if count == 0:
                    print("No cache entries found.")
                    return

                print(f"Found {count} cache entries")
                print("Clearing all cache entries...")

                URLEnrichmentCache.query.delete()
                db.session.commit()

                print(f"✓ Cleared {count} cache entries")

            print()
            print("Cache cleared successfully!")
            print("=" * 60)

        except Exception as e:
            print(f"✗ Error clearing cache: {e}")
            print("=" * 60)
            sys.exit(1)

if __name__ == '__main__':
    url = sys.argv[1] if len(sys.argv) > 1 else None
    clear_cache(url)
