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
- **Supported IOC Types**: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, and more
- **Risk Classification**: Severity levels (Low, Medium, High, Critical) with confidence scoring
- **TLP Support**: Traffic Light Protocol (WHITE, GREEN, AMBER, RED) for information sharing
- **Tagging System**: Organize IOCs with customizable colored tags
- **IOC Expiration**: Automatic TTL-based expiration with configurable policies
- **Collaborative Review**: Mark IOCs for review to enable collaborative editing by any user

### Threat Intelligence Enrichment
- **VirusTotal Integration**: Automatic malware analysis and reputation scoring
- **URLScan.io Integration**: URL screenshot and analysis
- **GeoIP Lookup**: Geographic location data for IP addresses
- **ASN Lookup**: Autonomous System Number and organization information
- **Caching**: Intelligent caching to reduce API calls and improve performance

### Collaboration & Analysis
- **IOC Relationships**: Link related indicators (resolves_to, contains, communicates_with, etc.)
- **Comments & Discussions**: Threaded comments with @mentions and Markdown support
- **YARA Rule Generation**: Auto-generate YARA and YARA-X detection rules
- **STIX 2.1 Export**: Export IOCs in STIX format for TAXII sharing
- **Audit Logging**: Complete audit trail of all actions with user tracking
- **Change Tracking**: Track who created and last updated each IOC

### Reporting & Automation
- **Email Reports**: Automated daily and weekly reports with statistics and trends
- **Dashboard**: Real-time metrics and visualizations
- **Search & Filter**: Advanced filtering by type, severity, tags, review status, and date ranges
- **Bulk Operations**: Import and export IOCs (coming soon)

### Administration & Configuration
- **Admin Panel**: Centralized administration interface
- **Reports Configuration**: Web-based email/SMTP configuration with hot-reload
- **API Key Management**: Secure API key configuration (VirusTotal, URLScan.io, etc.)
- **Audit Logs Viewer**: Search, filter, and purge audit logs with clickable resource links
- **User Management**: Create, edit, and manage user accounts and permissions

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

# VirusTotal API
VIRUSTOTAL_API_KEY=your-virustotal-api-key

# URLScan.io API
URLSCAN_API_KEY=your-urlscan-api-key

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
6. Click **Create IOC**

### Enriching IOCs

Click the **Enrich IOC** button on any IOC detail page to:
- Fetch VirusTotal analysis for hashes and URLs
- Get URLScan.io screenshots for URLs
- Lookup GeoIP data for IP addresses
- Retrieve ASN information

### Creating Relationships

Link related IOCs together:
1. Open an IOC detail page
2. Click **Add Relationship** in the Related IOCs section
3. Search for target IOC
4. Select relationship type (resolves_to, contains, etc.)
5. Add optional notes

### Generating YARA Rules

1. Open any hash-based IOC
2. Click **Generate YARA**
3. Toggle between YARA and YARA-X syntax
4. Copy or download the rule

### Commenting

Add comments to IOCs for collaboration:
- Use **Markdown** formatting for rich text
- **@mention** users to notify them
- **Reply** to create threaded discussions
- **Edit/Delete** your own comments

### IOC Review Workflow

Enable collaborative review for quality assurance:
1. Open an IOC detail page
2. Toggle the **"To be reviewed"** switch in the metadata section
3. IOC will show a review badge in the IOC list
4. Any User or Admin can now edit the IOC (not just the creator)
5. After review is complete, toggle the switch again to remove review status
6. All review status changes are logged in the audit trail

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


### IOC Expiration

Automatically expire old IOCs:

```bash
# Configure in .env
IOC_DEFAULT_TTL_DAYS=90
IOC_AUTO_EXPIRE_ENABLED=True

# Schedule expiration check
0 2 * * * cd /path/to/IoCManager && /path/to/venv/bin/python scripts/expire_iocs.py
```

### Audit Logging & Compliance

Comprehensive audit trail for compliance and forensics:

**What's Logged**:
- User authentication (LOGIN, LOGOUT)
- IOC operations (CREATE, UPDATE, DELETE, ENRICH, EXPORT)
- User management (CREATE, UPDATE, DELETE users)
- Configuration changes (API keys, email settings)
- Comment activity
- Review status changes

**Audit Log Features**:
- **Smart Filtering**: Filter by resource type, action, user, and date range
- **Resource Linking**: Click on IOCs, users, or comments to view details
- **Automatic Purge**: Remove logs older than 30 days to manage database size
- **Export Capability**: Generate compliance reports from audit data

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
| **Admin** | Full access: manage users, delete any content, access admin panel, configure system settings |
| **User** | Create, edit own IOCs and comments, edit IOCs marked for review |
| **Viewer** | Read-only access to IOCs and comments |

### IOC Review Feature

IOCs can be marked for collaborative review, allowing any User or Admin to edit them regardless of who created them. This feature enables:
- **Quality Assurance**: Team members can review and improve IOCs
- **Collaborative Enrichment**: Multiple analysts can contribute to IOC details
- **Badge Visibility**: IOCs marked for review show a clear badge in the IOC list
- **Audit Tracking**: All review status changes are logged in the audit trail

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
  - QR code setup with standard authenticator apps (Google Authenticator, Authy, Microsoft Authenticator)
  - 10 one-time backup recovery codes per user
  - Rate limiting to prevent brute force attacks (10 attempts per 15 minutes)
  - Encrypted secret storage using Fernet symmetric encryption
  - Backup codes hashed with bcrypt (same as passwords)
  - Complete audit trail of MFA events (enable, disable, login attempts)
  - Admin visibility of MFA status for all users
- **Comprehensive Audit Logging**: Complete audit trail tracking:
  - User actions (CREATE, UPDATE, DELETE, LOGIN, LOGOUT)
  - IOC operations (create, edit, enrich, export, review status changes)
  - User management operations
  - Configuration changes
  - Searchable audit log viewer with smart filtering and resource linking

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
│   │   └── ...
│   ├── routes/               # Flask blueprints
│   │   ├── ioc.py
│   │   ├── auth.py
│   │   ├── comment.py
│   │   └── ...
│   ├── services/             # Business logic
│   │   ├── virustotal.py
│   │   ├── urlscan.py
│   │   ├── yara_generator.py
│   │   └── report_generator.py
│   ├── utils/                # Utilities
│   │   └── markdown.py
│   └── templates/            # Jinja2 templates
├── scripts/                  # Management scripts
│   ├── init_db.py
│   ├── download_asn_db.py
│   ├── send_daily_report.py
│   ├── send_weekly_report.py
│   └── expire_iocs.py
├── instance/                 # Instance-specific files
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

## 📚 Documentation

comming soon... 

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

**Issue**: Database errors or missing columns
- **Solution**: Run migration scripts:
  ```bash
  python scripts/migrate_add_updated_by.py
  python scripts/migrate_add_expiration.py
  ```

**Issue**: Permission denied errors
- **Solution**: Ensure scripts are executable: `chmod +x scripts/*.py`


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Bootstrap 5](https://getbootstrap.com/) - UI framework
- [VirusTotal](https://www.virustotal.com/) - Malware analysis
- [URLScan.io](https://urlscan.io/) - URL analysis
- [MaxMind](https://www.maxmind.com/) - GeoIP data
- [YARA](https://virustotal.github.io/yara/) - Malware detection rules
- [STIX](https://oasis-open.github.io/cti-documentation/) - Threat intelligence format

## 📧 Contact

- **Project Link**: https://github.com/JMousqueton/IoCManager
- **Issues**: https://github.com/JMousqueton/IoCManager/issues
- **Documentation**: https://github.com/JMousqueton/IoCManager/wiki

## 🌟 Show Your Support

Give a ⭐️ if this project helped you!

---

**Built with ❤️ for the cybersecurity community**
