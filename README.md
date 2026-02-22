# IOC Manager by Julien Mousqueton

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive web-based platform for managing, enriching, and analyzing Indicators of Compromise (IOCs). Built for Security Operations Centers (SOCs), Computer Emergency Response Teams (CERTs), and threat intelligence teams.

## 🎬 Demo

![IOC Manager Demo](.github/IoCManager.gif)

## 🌟 Features

### Core Functionality
- **IOC Management**: Create, read, update, and delete IOCs with support for multiple indicator types
- **Supported IOC Types**: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, SHA512, SSDEEP, Email
- **Risk Classification**: Severity levels (Low, Medium, High, Critical) with confidence scoring
- **TLP Support**: Traffic Light Protocol (WHITE, GREEN, AMBER, RED) for information sharing
- **Tagging System**: Organize IOCs with customizable colored tags
- **IOC Expiration**: Automatic TTL-based expiration with configurable policies
- **Collaborative Review**: Mark IOCs for review to enable collaborative editing by any user
- **Lifecycle Management**: Full approval workflow with Draft → In Review → Active → Archived states
- **Operating System Tagging**: Tag hash-based IOCs (MD5, SHA1, SHA256, SHA512, SSDEEP) with target OS (Windows x64/x86, Linux ELF, macOS, Android APK, and more)
- **IOC Sharing**: Generate anonymized shareable links for individual IOCs

### Threat Intelligence Enrichment
- **VirusTotal Integration**: Automatic malware analysis, reputation scoring, and MITRE ATT&CK mapping for hashes and URLs
- **URLScan.io Integration**: URL screenshot, verdict, and page analysis
- **GeoIP Lookup**: Geographic location data for IP addresses (MaxMind GeoLite2)
- **ASN Lookup**: Autonomous System Number and organization information
- **Domain Enrichment**: WHOIS data, DNS records (A, AAAA, MX, NS, TXT), and SSL/TLS certificate details
- **URL Enrichment**: HTTP headers, server fingerprinting, technology detection, security headers, and favicon hashing
- **Smart Caching**: Intelligent per-service database caching to minimize API calls
- **Cache Refresh**: Force-refresh stale enrichment data with the **Refresh IOC Enrichment** button

### Collaboration & Analysis
- **IOC Relationships**: Link related indicators (resolves_to, contains, communicates_with, downloads_from, drops, connects_to, etc.)
- **Relationship Graph**: Interactive multi-hop visualization of IOC relationships powered by Cytoscape.js (1–3 hop traversal, multiple layouts, dark mode support)
- **Comments & Discussions**: Threaded comments with @mentions and Markdown support
- **YARA Rule Generation**: Auto-generate YARA and YARA-X detection rules for all IOC types
- **Hunting Queries**: Auto-generate ready-to-use threat hunting queries for **Splunk**, **KQL (Microsoft Sentinel / Defender XDR)**, **Sigma**, and **CrowdStrike Falcon**
- **STIX 2.1 Export**: Export IOCs in STIX format for TAXII sharing
- **Audit Logging**: Complete audit trail of all actions with user tracking
- **Change Tracking**: Track who created and last updated each IOC

### Reporting & Automation
- **Email Reports**: Automated daily and weekly reports with statistics and trends
- **Lifecycle Digest**: Daily email digest of pending approvals, approvals, rejections, and archives
- **Dashboard**: Real-time metrics and visualizations
- **Search & Filter**: Advanced filtering by type, severity, tags, lifecycle status, and date ranges
- **Bulk Import**: Import multiple IOCs at once

### User Interface
- **Dark Mode**: Toggle between light and dark themes with persistent preference
- **Responsive Design**: Optimized for desktop and mobile browsers
- **Relationship Graph View**: Visual graph alongside the traditional list view on IOC detail pages

### Administration & Configuration
- **Admin Panel**: Centralized administration interface
- **Reports Configuration**: Web-based email/SMTP configuration with hot-reload
- **API Key Management**: Secure API key configuration (VirusTotal, URLScan.io, etc.)
- **Audit Logs Viewer**: Search, filter, and purge audit logs with clickable resource links
- **User Management**: Create, edit, and manage user accounts and permissions
- **Reviewer Management**: Grant or revoke the reviewer flag per user (independent of role)
- **Operating System Management**: Configure target OS options for hash IOCs

### Security & Access Control
- **Role-Based Access Control (RBAC)**: Admin, User, and Viewer roles
- **Multi-Factor Authentication (MFA)**: Optional per-user TOTP-based 2FA with QR code setup, backup codes, and rate limiting
- **User Management**: User registration, authentication, and session management
- **Registration Control**: Enable/disable public registration
- **Comprehensive Audit Trail**: Track all user actions, IOC changes, and system events
- **Admin Audit Viewer**: Advanced search and filtering of audit logs with smart resource linking

## 📋 Requirements

- Python 3.8+
- SQLite (default) or PostgreSQL/MySQL
- SMTP server (for email reports)
- VirusTotal API key (optional)
- URLScan.io API key (optional)
- MaxMind GeoLite2 databases (optional, for GeoIP/ASN)

## 🚀 Quick Start

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/JMousqueton/IoCManager.git
   cd IoCManager
   ```

2. **Create virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings (API keys, SMTP, etc.)
   nano .env
   ```

5. **Initialize database**
   ```bash
   python scripts/init_db.py
   ```

6. **Download GeoIP database** (optional)
   ```bash
   python scripts/download_asn_db.py
   ```

7. **Start the application**
   ```bash
   python run.py
   ```

8. **Access the application**
   - Open browser: http://localhost:5000
   - Default admin credentials: `admin` / `admin` (change immediately!)

## ⚙️ Configuration

### Environment Variables

Configuration can be done via:
1. **`.env` file** - Edit manually for initial setup
2. **Admin Panel** (recommended) - Web-based configuration with hot-reload for:
   - API keys (VirusTotal, URLScan.io)
   - Email/SMTP settings
   - Report recipients

Key configuration options in `.env`:

```bash
# Flask Configuration
SECRET_KEY=your-secret-key-here
FLASK_ENV=development
FLASK_DEBUG=True

# Server Binding
FLASK_HOST=127.0.0.1
FLASK_PORT=5000

# VirusTotal API
VIRUSTOTAL_API_KEY=your-virustotal-api-key
VIRUSTOTAL_CACHE_DAYS=7       # Cache duration (default: 7 days)
VIRUSTOTAL_RATE_LIMIT=4       # Requests per minute (free tier: 4)

# URLScan.io API
URLSCAN_API_KEY=your-urlscan-api-key
URLSCAN_CACHE_DAYS=7
URLSCAN_RATE_LIMIT=1

# Domain & URL Enrichment Cache
DOMAIN_ENRICHMENT_CACHE_DAYS=30
URL_ENRICHMENT_CACHE_DAYS=7

# Email Reports
REPORT_ENABLED=True
DAILY_REPORT_RECIPIENTS=cert-team@example.com
WEEKLY_REPORT_RECIPIENTS=cert-team@example.com,management@example.com

# SMTP Configuration
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@example.com
MAIL_PASSWORD=your-app-password

# IOC Expiration
IOC_DEFAULT_TTL_DAYS=90
IOC_AUTO_EXPIRE_ENABLED=True

# IOC Lifecycle Management
DRAFT_RETENTION_DAYS=30        # Auto-archive drafts older than N days
NOTIFICATION_RETENTION_DAYS=7  # Purge processed notifications after N days

# Authentication
REGISTRATION_ENABLED=False  # Disable public registration
```

See `.env.example` for all available options.

## 📖 Usage

### Creating an IOC

1. Navigate to **Add IOC** from the menu
2. Select IOC type (IPv4, Domain, Hash, etc.)
3. Enter the IOC value
4. Set severity, confidence, and TLP level
5. Add description and tags
6. For hash types (MD5, SHA1, SHA256, etc.), optionally select a **target Operating System**
7. Choose a **Lifecycle Status**: *To be reviewed* (default), *Active*, or *Draft*
8. Click **Create IOC**

> IOCs created as **To be reviewed** are immediately placed in the approval queue and reviewers are notified.

### Enriching IOCs

Click **Enrich IOC** on any IOC detail page to automatically fetch threat intelligence:
- **IP addresses** — GeoIP location, ASN, and organization data
- **Hashes** — VirusTotal malware analysis, detection rate, MITRE ATT&CK techniques
- **URLs** — URLScan.io screenshot/verdict, VirusTotal URL analysis, HTTP headers, server fingerprinting, GeoIP of resolved IP
- **Domains** — WHOIS registration data, DNS records (A, AAAA, MX, NS, TXT), SSL/TLS certificates

Once enriched, the button changes to **Refresh IOC Enrichment** — clicking it clears the service cache and re-fetches fresh data from each source.

### Creating Relationships

Link related IOCs together:
1. Open an IOC detail page
2. Click **Add Relationship** in the Related IOCs section
3. Search for target IOC
4. Select relationship type (resolves_to, contains, downloads_from, etc.)
5. Add optional notes

The **Graph View** tab on the detail page visualizes the full relationship network with configurable hop depth (1–3).

### Generating YARA Rules

1. Open any IOC detail page
2. Click **Generate YARA**
3. Copy or download the rule (`.yar`)
4. Toggle to YARA-X syntax if needed (`.yarax`)

Supported for all IOC types: hashes (uses VT enrichment for additional hashes), IPs, domains, URLs.

### Generating Hunting Queries

1. Open any IOC detail page
2. Click **Hunting Queries**
3. Select a platform tab: **Splunk**, **KQL / Sentinel**, **Sigma**, or **CrowdStrike**
4. Copy to clipboard or download with the native file extension (`.spl`, `.kql`, `.yml`, `.fql`)

Queries use enrichment data where available (e.g. all known hashes from VirusTotal). Timeframe defaults to the last 30 days — adjust index names and table names for your environment.

### Commenting

Add comments to IOCs for collaboration:
- Use **Markdown** formatting for rich text
- **@mention** users to notify them
- **Reply** to create threaded discussions
- **Edit/Delete** your own comments

### Sharing IOCs

Click **Share** on any IOC detail page to copy an anonymized shareable link. The shared view strips sensitive metadata for safe external sharing.

### IOC Lifecycle Management

IOCs follow a structured approval workflow to ensure quality and accountability.

#### States

| State | Description |
|-------|-------------|
| **Draft** | Work in progress — only the creator and admins can see and edit it |
| **In Review** | Submitted for approval — reviewers are notified and can approve or reject |
| **Active** | Approved and operational — visible to all users |
| **Archived** | Retired — kept for historical reference, no longer active |

#### Workflow

```
Draft ──→ In Review ──→ Active ──→ Archived
            │                         ↑
            └─── (rejected) ──→ Draft   └─── Restore
```

#### For IOC Creators

1. Create an IOC — it defaults to **In Review** and reviewers are notified automatically
2. Alternatively, save as **Draft** to continue editing before submitting
3. On a Draft IOC, click **Submit for Review** when ready
4. Once approved, the IOC becomes **Active**
5. If rejected, the IOC returns to **Draft** with a rejection reason you can address

#### For Reviewers / Admins

1. A badge in the navbar shows the number of IOCs pending review
2. Navigate to **Approvals** in the top menu to see the full queue
3. On any IOC in review, click **Approve** to make it active or **Reject** with a reason
4. Reviewers can also **Archive** active IOCs and **Restore** archived ones

#### Marking for Review (quick path)

On any **Active** IOC detail page:
1. Toggle the **"To be reviewed"** switch
2. The lifecycle status automatically moves to **In Review** and reviewers are notified
3. Toggling it off restores the status to **Active**

#### Reviewer Role

The reviewer flag is independent of the user's role and can be granted to any user:
1. Navigate to **Admin → Reviewers**
2. Click **Grant** next to any user to give them reviewer privileges
3. Click **Revoke** to remove reviewer access

### Multi-Factor Authentication (MFA)

Enhance account security with optional TOTP-based two-factor authentication:

**Enabling MFA**:
1. Navigate to your profile page
2. Click **"Enable MFA"** in the Multi-Factor Authentication section
3. Scan the QR code with your authenticator app (Google Authenticator, Authy, Microsoft Authenticator)
4. Enter the 6-digit verification code to confirm setup
5. Save your 10 backup codes in a secure location (each can only be used once)

**Logging in with MFA**:
1. Enter your username and password as usual
2. You'll be redirected to an MFA verification page
3. Enter the 6-digit code from your authenticator app
4. Alternatively, check "Use a backup code instead" and enter one of your backup codes

**Managing MFA**:
- **View Backup Codes**: See how many backup codes you have remaining
- **Regenerate Codes**: Generate new backup codes if you've used most of them (requires MFA verification)
- **Disable MFA**: Turn off MFA protection (requires password + current MFA code)

**Security Features**:
- Rate limiting: Maximum 10 failed verification attempts per 15 minutes
- Session timeout: MFA verification must be completed within 5 minutes
- Backup codes: 10 one-time use codes for device loss scenarios
- Audit logging: All MFA events (enable, disable, login attempts) are logged
- Admin visibility: Admins can see which users have MFA enabled

**Note**: MFA is optional and configured per-user. Existing users are not affected when MFA is added to the system.

### Admin Panel (Admin Only)

Access comprehensive administration features:

**API Keys Tab**:
- Configure VirusTotal API key
- Configure URLScan.io API key
- Hot-reload configuration without restart

**Reports Tab**:
- Configure SMTP server settings (server, port, TLS/SSL)
- Set email credentials
- Configure report recipients (daily/weekly)
- Enable/disable automated reports
- Changes apply immediately without restart

**Audit Logs Tab**:
- Search and filter audit logs by:
  - Resource type (IOC, User, Tag, Configuration, Comment)
  - Action (CREATE, UPDATE, DELETE, LOGIN, ENRICH, EXPORT, SEARCH)
  - User
  - Date range
- Smart filtering: Selecting "IOC" includes IOC, IOCRelationship, and Comment entries
- Click on resources to view details (opens in new tab)
- Purge logs older than 30 days

**Users Tab**:
- Create, edit, and delete user accounts
- Assign roles (Admin, User, Viewer)
- Activate/deactivate accounts
- View user statistics (IOCs created, audit logs)

**Reviewers Tab**:
- Grant or revoke reviewer privileges per user
- Independent of the user's role

**Operating Systems Tab**:
- Manage target OS options displayed for hash-type IOCs
- Customize icons and descriptions

## 🔧 Advanced Features

### Email Reports

Configure automated reports in `.env`:

```bash
REPORT_ENABLED=True
DAILY_REPORT_RECIPIENTS=team@example.com
WEEKLY_REPORT_RECIPIENTS=team@example.com,management@example.com
```

Schedule with cron:
```bash
# Daily report at 8 AM
0 8 * * * cd /path/to/IoCManager && /path/to/venv/bin/python scripts/send_daily_report.py

# Weekly report at 8 AM every Monday
0 8 * * 1 cd /path/to/IoCManager && /path/to/venv/bin/python scripts/send_weekly_report.py
```

### IOC Lifecycle Automation

Schedule lifecycle tasks with cron:

```bash
# Daily lifecycle digest email (notifies reviewers of pending IOCs and creators of decisions)
0 8 * * * cd /path/to/IoCManager && PYTHONPATH=. venv/bin/python3 scripts/send_daily_lifecycle_digest.py >> /var/log/iocmanager-digest.log 2>&1

# Retention policy enforcement (auto-archives stale drafts and expired active IOCs)
0 2 * * * cd /path/to/IoCManager && PYTHONPATH=. venv/bin/python3 scripts/enforce_retention_policies.py >> /var/log/iocmanager-retention.log 2>&1
```

Configure retention in `.env`:
```bash
DRAFT_RETENTION_DAYS=30        # Drafts untouched for 30 days → auto-archived
NOTIFICATION_RETENTION_DAYS=7  # Processed notifications purged after 7 days
```

### IOC Expiration

Automatically expire old IOCs:

```bash
# Configure in .env
IOC_DEFAULT_TTL_DAYS=90
IOC_AUTO_EXPIRE_ENABLED=True

# Schedule expiration check
0 2 * * * cd /path/to/IoCManager && /path/to/venv/bin/python scripts/expire_iocs.py
```

### Automated Deployment

Use `update.sh` for production deployments:
- Git update checking with backup of code and database
- Dependency management and automatic migration runs
- Systemd service restart (`iocmanager`) and health check
- Automatic rollback on failure
- Logs to `/var/log/iocmanager-update.log`

### Audit Logging & Compliance

**What's Logged**:
- User authentication (LOGIN, LOGOUT)
- IOC operations (CREATE, UPDATE, DELETE, ENRICH, EXPORT)
- User management (CREATE, UPDATE, DELETE users)
- Configuration changes (API keys, email settings)
- Comment activity
- Review and lifecycle status changes

**Accessing Audit Logs** (Admin only):
1. Navigate to **Admin → Audit Logs**
2. Use filters to find specific events
3. Click on resources for detailed view
4. Use purge button to clean old logs

### STIX 2.1 Export

Export IOCs for TAXII sharing:
1. Navigate to IOC detail page
2. Click **Export STIX**
3. Download STIX 2.1 JSON bundle

## 🎨 User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access: manage users, delete any content, access admin panel, configure system settings. Can approve/reject/archive/restore IOCs. |
| **User** | Create and edit own IOCs and comments. Can submit IOCs for review. Can edit IOCs marked for review. |
| **Viewer** | Read-only access to IOCs and comments |

### Reviewer Flag

The **Reviewer** flag is a permission modifier independent of the user role. It can be combined with any role:

| Permission | Viewer | User | Admin | Reviewer (any role) |
|------------|:------:|:----:|:-----:|:-------------------:|
| View IOCs | ✓ | ✓ | ✓ | ✓ |
| Create IOCs | | ✓ | ✓ | |
| Edit own IOCs | | ✓ | ✓ | |
| Submit for review | | ✓ | ✓ | |
| **Approve / Reject** | | | ✓ | **✓** |
| **Archive / Restore** | | | ✓ | **✓** |
| Admin panel | | | ✓ | |

Reviewer access is managed in **Admin → Reviewers**.

## 📊 Dashboard Metrics

The dashboard provides:
- Total IOCs count
- Active vs. Inactive indicators
- Severity distribution
- Recently added IOCs
- Enrichment statistics
- User activity

## 🔒 Security

- **CSRF Protection**: All forms protected with CSRF tokens
- **Session Management**: Secure session handling with configurable timeouts
- **Password Hashing**: Werkzeug password hashing (bcrypt)
- **SQL Injection Prevention**: SQLAlchemy ORM with parameterized queries
- **XSS Prevention**: Markdown sanitization with Bleach
- **Multi-Factor Authentication (MFA)**: Optional per-user TOTP-based 2FA:
  - QR code setup with standard authenticator apps
  - 10 one-time backup recovery codes per user
  - Rate limiting (10 attempts per 15 minutes)
  - Encrypted secret storage using Fernet symmetric encryption
  - Backup codes hashed with bcrypt
  - Complete audit trail of MFA events
- **Comprehensive Audit Logging**: All user actions, IOC operations, and configuration changes

## 🗂️ Project Structure

```
IoCManager/
├── app/
│   ├── __init__.py           # Flask app factory
│   ├── config.py             # Configuration
│   ├── models/               # Database models
│   │   ├── ioc.py
│   │   ├── user.py
│   │   ├── comment.py
│   │   ├── cache.py
│   │   ├── notification.py
│   │   ├── operating_system.py
│   │   └── ...
│   ├── routes/               # Flask blueprints
│   │   ├── ioc.py
│   │   ├── auth.py
│   │   ├── admin.py
│   │   ├── comment.py
│   │   └── ...
│   ├── services/             # Business logic
│   │   ├── virustotal.py
│   │   ├── urlscan.py
│   │   ├── geoip.py
│   │   ├── domain_enrichment.py
│   │   ├── url_enrichment.py
│   │   ├── yara_generator.py
│   │   ├── hunting_query_generator.py
│   │   ├── report_generator.py
│   │   └── notification_service.py
│   ├── utils/                # Utilities
│   │   └── markdown.py
│   └── templates/            # Jinja2 templates
├── scripts/                  # Management & automation scripts
│   ├── init_db.py
│   ├── download_asn_db.py
│   ├── send_daily_report.py
│   ├── send_weekly_report.py
│   ├── expire_iocs.py
│   ├── send_daily_lifecycle_digest.py
│   └── enforce_retention_policies.py
├── instance/                 # Instance-specific files (DB, uploads)
├── update.sh                 # Automated deployment script
├── .env                      # Environment variables
├── requirements.txt          # Python dependencies
└── run.py                    # Application entry point
```

## 🛠️ Development

### Running in Development Mode

```bash
export FLASK_ENV=development
export FLASK_DEBUG=True
python run.py
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guide
- Write docstrings for functions and classes
- Add tests for new features
- Update documentation as needed

## 🐛 Troubleshooting

### Common Issues

**Issue**: Email reports not sending
- **Solution**: Check SMTP settings in `.env`, verify `REPORT_ENABLED=True`

**Issue**: VirusTotal enrichment failing
- **Solution**: Verify API key, check rate limits (4 requests/minute for free tier)

**Issue**: GeoIP data not available
- **Solution**: Run `python scripts/download_asn_db.py` to download MaxMind databases

**Issue**: Permission denied errors
- **Solution**: Ensure scripts are executable: `chmod +x scripts/*.py`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Bootstrap 5](https://getbootstrap.com/) - UI framework
- [Cytoscape.js](https://cytoscape.org/) - Graph visualization
- [VirusTotal](https://www.virustotal.com/) - Malware analysis
- [URLScan.io](https://urlscan.io/) - URL analysis
- [MaxMind](https://www.maxmind.com/) - GeoIP data
- [YARA](https://virustotal.github.io/yara/) - Malware detection rules
- [STIX](https://oasis-open.github.io/cti-documentation/) - Threat intelligence format
- [Sigma](https://sigmahq.io/) - Generic SIEM detection format

## 📧 Contact

- **Project Link**: https://github.com/JMousqueton/IoCManager
- **Issues**: https://github.com/JMousqueton/IoCManager/issues

## 🌟 Show Your Support

Give a ⭐️ if this project helped you!

---

**Built with ❤️ for the cybersecurity community**
