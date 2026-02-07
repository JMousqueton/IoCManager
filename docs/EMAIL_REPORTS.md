# Email Reports Configuration

IOC Manager can automatically send daily and weekly reports to configured recipients, providing insights into IOC trends, new threats, and system activity.

## Features

### Daily Report
- **New IOCs**: List of IOCs added in the last 24 hours
- **High Severity IOCs**: Critical and high severity indicators from the last day
- **Active IOC Count**: Total active indicators
- **Enrichment Success Rate**: Percentage of IOCs successfully enriched
- **IOC Distribution**: Breakdown by IOC type

### Weekly Report
- **Weekly Summary**: New IOCs with week-over-week comparison
- **Severity Trends**: Changes in IOC severity distribution
- **Top IOC Types**: Most common indicator types
- **Top Sources**: Most active IOC sources
- **User Activity**: Most active users and actions
- **Expiring IOCs**: Indicators expiring in the next 7 days

## Configuration

### 1. Enable Email Reports

Edit your `.env` file:

```bash
# Email Reports Configuration
REPORT_ENABLED=True
DAILY_REPORT_RECIPIENTS=cert-team@example.com,analyst1@example.com
WEEKLY_REPORT_RECIPIENTS=cert-team@example.com,management@example.com,ciso@example.com
```

### 2. Configure SMTP Settings

Ensure your SMTP settings are configured in `.env`:

```bash
# Email Configuration (SMTP)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USE_SSL=False
MAIL_USERNAME=ioc-manager@example.com
MAIL_PASSWORD=your-app-specific-password
MAIL_DEFAULT_SENDER=ioc-manager@example.com
```

#### SMTP Provider Examples

**Gmail**:
```bash
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password  # Use App Password, not regular password
```

**Office 365**:
```bash
MAIL_SERVER=smtp.office365.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@company.com
MAIL_PASSWORD=your-password
```

**SendGrid**:
```bash
MAIL_SERVER=smtp.sendgrid.net
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=apikey
MAIL_PASSWORD=your-sendgrid-api-key
```

## Scheduling Reports

### Option 1: Cron Jobs (Linux/macOS)

#### Daily Report (8:00 AM every day)

Edit crontab:
```bash
crontab -e
```

Add:
```bash
# IOC Manager Daily Report - 8:00 AM daily
0 8 * * * cd /path/to/IoCManager && /path/to/venv/bin/python scripts/send_daily_report.py >> logs/daily_report.log 2>&1
```

#### Weekly Report (8:00 AM every Monday)

```bash
# IOC Manager Weekly Report - 8:00 AM every Monday
0 8 * * 1 cd /path/to/IoCManager && /path/to/venv/bin/python scripts/send_weekly_report.py >> logs/weekly_report.log 2>&1
```

#### Complete Cron Example

```bash
# IOC Manager Scheduled Tasks
# Daily report at 8:00 AM
0 8 * * * cd /path/to/IoCManager && /path/to/venv/bin/python scripts/send_daily_report.py >> logs/daily_report.log 2>&1

# Weekly report at 8:00 AM every Monday
0 8 * * 1 cd /path/to/IoCManager && /path/to/venv/bin/python scripts/send_weekly_report.py >> logs/weekly_report.log 2>&1

# IOC expiration check at 2:00 AM daily
0 2 * * * cd /path/to/IoCManager && /path/to/venv/bin/python scripts/expire_iocs.py >> logs/expire_iocs.log 2>&1
```

### Option 2: Systemd Timers (Linux)

#### Daily Report Timer

Create `/etc/systemd/system/ioc-daily-report.service`:
```ini
[Unit]
Description=IOC Manager Daily Report
After=network.target

[Service]
Type=oneshot
User=ioc-user
WorkingDirectory=/path/to/IoCManager
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/python scripts/send_daily_report.py
StandardOutput=append:/path/to/IoCManager/logs/daily_report.log
StandardError=append:/path/to/IoCManager/logs/daily_report.log
```

Create `/etc/systemd/system/ioc-daily-report.timer`:
```ini
[Unit]
Description=IOC Manager Daily Report Timer
Requires=ioc-daily-report.service

[Timer]
OnCalendar=*-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

#### Weekly Report Timer

Create `/etc/systemd/system/ioc-weekly-report.service`:
```ini
[Unit]
Description=IOC Manager Weekly Report
After=network.target

[Service]
Type=oneshot
User=ioc-user
WorkingDirectory=/path/to/IoCManager
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/python scripts/send_weekly_report.py
StandardOutput=append:/path/to/IoCManager/logs/weekly_report.log
StandardError=append:/path/to/IoCManager/logs/weekly_report.log
```

Create `/etc/systemd/system/ioc-weekly-report.timer`:
```ini
[Unit]
Description=IOC Manager Weekly Report Timer
Requires=ioc-weekly-report.service

[Timer]
OnCalendar=Mon *-*-* 08:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

#### Enable Timers

```bash
sudo systemctl daemon-reload
sudo systemctl enable ioc-daily-report.timer
sudo systemctl enable ioc-weekly-report.timer
sudo systemctl start ioc-daily-report.timer
sudo systemctl start ioc-weekly-report.timer
```

Check status:
```bash
sudo systemctl list-timers | grep ioc
```

### Option 3: Windows Task Scheduler

1. Open Task Scheduler
2. Create new task: "IOC Manager Daily Report"
3. Trigger: Daily at 8:00 AM
4. Action: Start a program
   - Program: `C:\path\to\venv\Scripts\python.exe`
   - Arguments: `scripts\send_daily_report.py`
   - Start in: `C:\path\to\IoCManager`

Repeat for weekly report with weekly trigger on Monday.

## Manual Testing

Test daily report:
```bash
# Activate virtual environment
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Run daily report
python scripts/send_daily_report.py
```

Test weekly report:
```bash
python scripts/send_weekly_report.py
```

## Troubleshooting

### No Email Received

1. **Check REPORT_ENABLED**:
   ```bash
   grep REPORT_ENABLED .env
   # Should show: REPORT_ENABLED=True
   ```

2. **Check Recipients**:
   ```bash
   grep REPORT_RECIPIENTS .env
   # Verify email addresses are correct
   ```

3. **Check SMTP Settings**:
   ```bash
   grep MAIL_ .env
   # Verify SMTP server, port, credentials
   ```

4. **Test SMTP Connection**:
   ```python
   from app import create_app, mail
   app = create_app()
   with app.app_context():
       with mail.connect() as conn:
           print("SMTP connection successful!")
   ```

5. **Check Logs**:
   ```bash
   tail -f logs/daily_report.log
   tail -f logs/weekly_report.log
   ```

### Gmail-Specific Issues

If using Gmail:
1. Enable "Less secure app access" OR use App Passwords
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Use App Password in MAIL_PASSWORD

### Office 365 Issues

If using O365:
1. Ensure account has SMTP AUTH enabled
2. May need to enable "Authenticated SMTP" in admin center
3. Use basic authentication (username/password)

## Customization

### Modify Report Content

Edit templates:
- Daily: `app/templates/email/daily_report.html`
- Weekly: `app/templates/email/weekly_report.html`

### Modify Report Logic

Edit service:
- `app/services/report_generator.py`

### Change Recipients Dynamically

Update recipients in `.env` without restarting:
```bash
# Edit .env
nano .env

# No restart needed - reads .env on each run
```

## Security Considerations

1. **Email Credentials**: Store SMTP password securely, use app-specific passwords
2. **TLP Compliance**: Reports respect TLP levels but contain sensitive data
3. **Recipient List**: Verify all recipients are authorized to receive IOC data
4. **Email Security**: Use TLS/SSL for SMTP connections
5. **Log Rotation**: Configure log rotation for report logs

## Best Practices

1. **Start with Daily Reports**: Enable daily reports first, add weekly later
2. **Test Recipients**: Start with a small recipient list for testing
3. **Monitor Logs**: Check logs regularly to ensure reports are sending
4. **Backup Schedule**: Document your cron/timer configuration
5. **Review Content**: Periodically review report content for relevance

## Disabling Reports

To disable reports temporarily:
```bash
# Edit .env
REPORT_ENABLED=False
```

To disable permanently:
```bash
# Remove cron jobs
crontab -e
# Comment out or remove IOC Manager report lines

# OR disable systemd timers
sudo systemctl stop ioc-daily-report.timer
sudo systemctl disable ioc-daily-report.timer
sudo systemctl stop ioc-weekly-report.timer
sudo systemctl disable ioc-weekly-report.timer
```
