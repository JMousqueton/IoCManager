# IOC Manager

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/flask-3.0+-green.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive web-based platform for managing, enriching, and analyzing Indicators of Compromise (IOCs). Built for Security Operations Centers (SOCs), Computer Emergency Response Teams (CERTs), and threat intelligence teams.

## 🌟 Features

### Core Functionality
- **IOC Management**: Create, read, update, and delete IOCs with support for multiple indicator types
- **Supported IOC Types**: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, Email, and more
- **Risk Classification**: Severity levels (Low, Medium, High, Critical) with confidence scoring
- **TLP Support**: Traffic Light Protocol (WHITE, GREEN, AMBER, RED) for information sharing
- **Tagging System**: Organize IOCs with customizable colored tags
- **IOC Expiration**: Automatic TTL-based expiration with configurable policies

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
- **Audit Logging**: Complete audit trail of all actions

### Reporting & Automation
- **Email Reports**: Automated daily and weekly reports with statistics and trends
- **Dashboard**: Real-time metrics and visualizations
- **Search & Filter**: Advanced filtering by type, severity, tags, and date ranges
- **Bulk Operations**: Import and export IOCs (coming soon)

### Security & Access Control
- **Role-Based Access Control (RBAC)**: Admin, User, and Viewer roles
- **User Management**: User registration, authentication, and session management
- **Registration Control**: Enable/disable public registration
- **Audit Trail**: Track all user actions and changes

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
   git clone https://github.com/yourusername/IoCManager.git
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
   - Default admin credentials: `admin` / `admin123` (change immediately!)

## ⚙️ Configuration

### Environment Variables

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

See [docs/EMAIL_REPORTS.md](docs/EMAIL_REPORTS.md) for detailed setup.

### IOC Expiration

Automatically expire old IOCs:

```bash
# Configure in .env
IOC_DEFAULT_TTL_DAYS=90
IOC_AUTO_EXPIRE_ENABLED=True

# Schedule expiration check
0 2 * * * cd /path/to/IoCManager && /path/to/venv/bin/python scripts/expire_iocs.py
```

### STIX 2.1 Export

Export IOCs for TAXII sharing:
1. Navigate to IOC detail page
2. Click **Export STIX**
3. Download STIX 2.1 JSON bundle

## 🎨 User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access: manage users, delete any content, access admin panel |
| **User** | Create, edit, delete own IOCs and comments |
| **Viewer** | Read-only access to IOCs and comments |

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
- **Audit Logging**: Complete audit trail of all actions

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
│   ├── send_daily_report.py
│   ├── send_weekly_report.py
│   └── expire_iocs.py
├── docs/                     # Documentation
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

### Database Migrations

Create new migration:
```bash
flask db migrate -m "Description of changes"
flask db upgrade
```

### Running Tests

```bash
pytest tests/
```

## 📚 Documentation

- [Email Reports Setup](docs/EMAIL_REPORTS.md) - Configure automated reports
- [IOC Expiration](docs/IOC_EXPIRATION.md) - TTL and expiration policies
- [API Documentation](docs/API.md) - REST API reference (coming soon)

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

**Issue**: Database errors
- **Solution**: Run migrations: `python scripts/migrate_add_*.py`

**Issue**: Permission denied errors
- **Solution**: Ensure scripts are executable: `chmod +x scripts/*.py`

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for more solutions.

## 🗺️ Roadmap

### Planned Features

- [ ] RESTful API with API key authentication
- [ ] Bulk import/export (CSV, JSON, MISP)
- [ ] Advanced search with boolean operators
- [ ] IOC watchlists/feeds
- [ ] MISP integration
- [ ] Dashboard charts and visualizations
- [ ] Dark mode
- [ ] File upload with hash extraction
- [ ] Machine learning-based IOC scoring

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

- **Project Link**: https://github.com/yourusername/IoCManager
- **Issues**: https://github.com/yourusername/IoCManager/issues
- **Documentation**: https://github.com/yourusername/IoCManager/wiki

## 🌟 Show Your Support

Give a ⭐️ if this project helped you!

---

**Built with ❤️ for the cybersecurity community**
