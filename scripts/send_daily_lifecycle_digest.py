#!/usr/bin/env python3
"""
Send daily lifecycle digest emails to all users with pending notifications.

Usage:
    PYTHONPATH=. venv/bin/python3 scripts/send_daily_lifecycle_digest.py

Cron example (daily at 08:00):
    0 8 * * * cd /opt/iocmanager && PYTHONPATH=. venv/bin/python3 scripts/send_daily_lifecycle_digest.py >> /var/log/iocmanager-digest.log 2>&1
"""

import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app import create_app
from app.services.notification_service import NotificationService

if __name__ == '__main__':
    app = create_app()
    print(f"[Digest] Starting daily lifecycle digest...")
    NotificationService.send_daily_digest(app)
    print(f"[Digest] Done.")
