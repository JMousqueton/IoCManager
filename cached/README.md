# Cached Directory

This directory stores cached files downloaded during IOC enrichment.

## Structure:
- favicon/ - Cached favicons from URL enrichment
  - Naming: {ioc_id}.{extension} (e.g., 123.png, 456.ico)

## Maintenance:
Files in this directory are referenced in the database. Do not delete manually.
Use scripts/clear_all_caches.py to manage cache entries.
