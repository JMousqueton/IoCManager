#!/usr/bin/env python3
"""
Clear All Enrichment Caches

This script clears all enrichment cache tables or specific cache types.
Useful when you want to force re-enrichment of IOCs.

Usage:
    python scripts/clear_all_caches.py                      # Clear ALL caches
    python scripts/clear_all_caches.py --type virustotal    # Clear specific cache
    python scripts/clear_all_caches.py --type url           # Clear URL cache
    python scripts/clear_all_caches.py --expired-only       # Clear only expired entries
"""

import os
import sys
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Create Flask app context
from app import create_app, db
from app.models.cache import (
    VirusTotalCache,
    ASLookupCache,
    URLScanCache,
    DomainEnrichmentCache,
    URLEnrichmentCache
)

app = create_app()

# Cache type mapping
CACHE_TYPES = {
    'virustotal': {
        'model': VirusTotalCache,
        'name': 'VirusTotal',
        'description': 'Hash lookup results'
    },
    'as': {
        'model': ASLookupCache,
        'name': 'AS Lookup',
        'description': 'Autonomous System lookups'
    },
    'urlscan': {
        'model': URLScanCache,
        'name': 'URLScan.io',
        'description': 'URL scan results'
    },
    'domain': {
        'model': DomainEnrichmentCache,
        'name': 'Domain Enrichment',
        'description': 'WHOIS, DNS, and certificate data'
    },
    'url': {
        'model': URLEnrichmentCache,
        'name': 'URL Enrichment',
        'description': 'HTTP headers, server info, SSL certificates'
    }
}


def clear_cache(cache_type=None, expired_only=False, dry_run=False):
    """Clear cache entries"""

    with app.app_context():
        print("=" * 70)
        if expired_only:
            print("CACHE CLEANUP - EXPIRED ENTRIES ONLY")
        elif dry_run:
            print("CACHE CLEANUP - DRY RUN (NO CHANGES)")
        else:
            print("CACHE CLEANUP - ALL ENTRIES")
        print("=" * 70)
        print()

        total_cleared = 0

        # Determine which caches to clear
        if cache_type:
            if cache_type not in CACHE_TYPES:
                print(f"✗ Unknown cache type: {cache_type}")
                print(f"Valid types: {', '.join(CACHE_TYPES.keys())}")
                sys.exit(1)
            caches_to_clear = {cache_type: CACHE_TYPES[cache_type]}
        else:
            caches_to_clear = CACHE_TYPES

        # Clear each cache
        for cache_key, cache_info in caches_to_clear.items():
            model = cache_info['model']
            name = cache_info['name']
            description = cache_info['description']

            print(f"📦 {name} Cache")
            print(f"   {description}")
            print()

            try:
                if expired_only:
                    # Clear only expired entries
                    count = model.query.filter(
                        model.expires_at < datetime.utcnow()
                    ).count()

                    if count == 0:
                        print(f"   No expired entries found")
                    else:
                        print(f"   Found {count} expired entries")

                        if not dry_run:
                            model.query.filter(
                                model.expires_at < datetime.utcnow()
                            ).delete()
                            db.session.commit()
                            print(f"   ✓ Cleared {count} expired entries")
                            total_cleared += count
                        else:
                            print(f"   [DRY RUN] Would clear {count} expired entries")
                else:
                    # Clear all entries
                    count = model.query.count()

                    if count == 0:
                        print(f"   No entries found")
                    else:
                        print(f"   Found {count} entries")

                        if not dry_run:
                            model.query.delete()
                            db.session.commit()
                            print(f"   ✓ Cleared {count} entries")
                            total_cleared += count
                        else:
                            print(f"   [DRY RUN] Would clear {count} entries")

                print()

            except Exception as e:
                print(f"   ✗ Error clearing {name} cache: {e}")
                print()
                db.session.rollback()

        # Summary
        print("=" * 70)
        if dry_run:
            print(f"DRY RUN COMPLETE - No changes made")
            print(f"Would have cleared {total_cleared} total entries")
        else:
            if total_cleared > 0:
                print(f"✓ Successfully cleared {total_cleared} total cache entries")
            else:
                print("No cache entries found to clear")
        print("=" * 70)
        print()


def show_cache_stats():
    """Show statistics for all caches"""

    with app.app_context():
        print("=" * 70)
        print("CACHE STATISTICS")
        print("=" * 70)
        print()

        total_entries = 0
        total_expired = 0

        for cache_key, cache_info in CACHE_TYPES.items():
            model = cache_info['model']
            name = cache_info['name']

            total = model.query.count()
            expired = model.query.filter(
                model.expires_at < datetime.utcnow()
            ).count()
            active = total - expired

            total_entries += total
            total_expired += expired

            print(f"📦 {name}")
            print(f"   Total:   {total:,} entries")
            print(f"   Active:  {active:,} entries")
            print(f"   Expired: {expired:,} entries")

            if total > 0:
                expired_pct = (expired / total) * 100
                print(f"   ({expired_pct:.1f}% expired)")

            print()

        print("=" * 70)
        print(f"TOTALS")
        print(f"   Total:   {total_entries:,} entries")
        print(f"   Active:  {(total_entries - total_expired):,} entries")
        print(f"   Expired: {total_expired:,} entries")
        print("=" * 70)
        print()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Clear enrichment caches for IOC Manager'
    )
    parser.add_argument(
        '--type',
        type=str,
        choices=list(CACHE_TYPES.keys()),
        help='Specific cache type to clear (default: all caches)'
    )
    parser.add_argument(
        '--expired-only',
        action='store_true',
        help='Only clear expired cache entries'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be cleared without actually clearing'
    )
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show cache statistics and exit'
    )

    args = parser.parse_args()

    if args.stats:
        show_cache_stats()
        return

    # Confirmation prompt (skip for dry run or expired only)
    if not args.dry_run and not args.expired_only:
        if args.type:
            cache_name = CACHE_TYPES[args.type]['name']
            confirm = input(f"⚠ Clear ALL {cache_name} cache entries? (yes/no): ").strip().lower()
        else:
            confirm = input("⚠ Clear ALL cache types? This will force re-enrichment of all IOCs. (yes/no): ").strip().lower()

        if confirm != 'yes':
            print("\nCancelled.")
            return

    clear_cache(
        cache_type=args.type,
        expired_only=args.expired_only,
        dry_run=args.dry_run
    )


if __name__ == '__main__':
    main()
