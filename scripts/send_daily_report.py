#!/usr/bin/env python3
"""
Send Daily IOC Report

Generates and sends daily IOC report to configured recipients.
Should be run via cron daily (e.g., at 8:00 AM).

Usage:
    python scripts/send_daily_report.py
"""

import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
load_dotenv()

from app import create_app
from app.services.report_generator import ReportGenerator

# Create Flask app
app = create_app()


def send_daily_report():
    """Generate and send daily report"""

    with app.app_context():
        print("=" * 60)
        print("IOC Manager - Daily Report")
        print("=" * 60)
        print()

        # Check if reports are enabled
        if not app.config.get('REPORT_ENABLED', False):
            print("✗ Reports are disabled (REPORT_ENABLED=False)")
            print("  To enable reports, set REPORT_ENABLED=True in .env")
            print("=" * 60)
            return

        # Get recipients
        recipients_str = app.config.get('DAILY_REPORT_RECIPIENTS', '')
        if not recipients_str:
            print("✗ No recipients configured")
            print("  Set DAILY_REPORT_RECIPIENTS in .env")
            print("=" * 60)
            return

        recipients = [email.strip() for email in recipients_str.split(',')]
        print(f"Recipients: {', '.join(recipients)}")
        print()

        # Generate report
        print("Generating daily report...")
        try:
            subject, html_content = ReportGenerator.generate_daily_report(app)
            print(f"✓ Report generated: {subject}")
        except Exception as e:
            print(f"✗ Error generating report: {e}")
            print("=" * 60)
            sys.exit(1)

        # Send report
        print(f"Sending report to {len(recipients)} recipient(s)...")
        try:
            success = ReportGenerator.send_report(app, subject, html_content, recipients)
            if success:
                print("✓ Report sent successfully")
            else:
                print("✗ Failed to send report")
                sys.exit(1)
        except Exception as e:
            print(f"✗ Error sending report: {e}")
            print("=" * 60)
            sys.exit(1)

        print()
        print("Daily report completed successfully!")
        print("=" * 60)


if __name__ == '__main__':
    send_daily_report()
