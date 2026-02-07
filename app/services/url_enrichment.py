"""
URL Enrichment Service
Handles HTTP header analysis, server detection, and technology fingerprinting with caching
"""

import json
import logging
import requests
import ssl
import socket
import os
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from flask import current_app
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from app import db
from app.models import URLEnrichmentCache

logger = logging.getLogger(__name__)


class URLEnrichmentService:
    """URL Enrichment Service with caching"""

    def __init__(self, cache_days=None):
        """
        Initialize URL Enrichment service

        Args:
            cache_days: Number of days to cache results (default: from config)
        """
        self.cache_days = cache_days or current_app.config.get('URL_ENRICHMENT_CACHE_DAYS', 7)

    def enrich_url(self, url, ioc_id=None):
        """
        Get enrichment data for a URL

        Args:
            url: URL to enrich
            ioc_id: IOC ID for saving favicon locally (optional)

        Returns:
            dict: Enrichment data including headers, server info, security headers
        """
        # Normalize URL
        url = url.strip()

        # Check cache first
        cached_data = self._check_cache(url)
        if cached_data:
            logger.info(f"Cache hit for URL: {url}")
            return cached_data

        # Cache miss - perform enrichment
        logger.info(f"Cache miss for URL: {url} - performing enrichment")
        enrichment_data = self._perform_enrichment(url, ioc_id)

        # Cache the results
        if enrichment_data and enrichment_data.get('status') != 'error':
            self._save_to_cache(url, enrichment_data)

        return enrichment_data

    def _check_cache(self, url):
        """Check if URL enrichment is cached and not expired"""
        try:
            cache_entry = URLEnrichmentCache.query.filter_by(url=url).first()

            if cache_entry:
                if cache_entry.is_expired():
                    logger.info(f"Cache entry expired for URL: {url}")
                    db.session.delete(cache_entry)
                    db.session.commit()
                    return None

                # Return cached data
                return {
                    'url': cache_entry.url,
                    'status_code': cache_entry.status_code,
                    'server': cache_entry.server,
                    'headers': json.loads(cache_entry.headers) if cache_entry.headers else {},
                    'technologies': json.loads(cache_entry.technologies) if cache_entry.technologies else [],
                    'security_headers': json.loads(cache_entry.security_headers) if cache_entry.security_headers else {},
                    'redirect_url': cache_entry.redirect_url,
                    'response_time': cache_entry.response_time,
                    'content_type': cache_entry.content_type,
                    'favicon_url': cache_entry.favicon_url,
                    'favicon_path': cache_entry.favicon_path,
                    'favicon_sha256': cache_entry.favicon_sha256,
                    'ssl_certificate': json.loads(cache_entry.ssl_certificate) if cache_entry.ssl_certificate else {},
                    'cached_at': cache_entry.cached_at.isoformat(),
                    'status': 'success'
                }

            return None

        except Exception as e:
            logger.error(f"Error checking cache for URL {url}: {e}")
            return None

    def _perform_enrichment(self, url, ioc_id=None):
        """Perform actual URL enrichment"""
        try:
            result = {
                'url': url,
                'status_code': None,
                'server': None,
                'headers': {},
                'technologies': [],
                'security_headers': {},
                'redirect_url': None,
                'response_time': None,
                'content_type': None,
                'favicon_url': None,
                'favicon_path': None,
                'favicon_sha256': None,
                'ssl_certificate': {},
                'status': 'success'
            }

            # Make HTTP request
            logger.info(f"Requesting URL: {url}")

            # Check if SSL verification should be disabled
            verify_ssl = not current_app.config.get('URL_ENRICHMENT_NO_SSL_CHECK', False)
            logger.info(f"SSL verification: {verify_ssl}")

            # Make request with timeout
            start_time = datetime.utcnow()
            response = requests.get(
                url,
                timeout=10,
                verify=verify_ssl,
                allow_redirects=True,
                headers={'User-Agent': 'IOC-Manager/1.0'}
            )
            end_time = datetime.utcnow()

            response_time = (end_time - start_time).total_seconds()

            logger.info(f"Response status: {response.status_code}, Time: {response_time}s")

            # Extract basic info
            result['status_code'] = response.status_code
            result['response_time'] = round(response_time, 3)
            result['content_type'] = response.headers.get('Content-Type', 'Unknown')

            # Extract all headers (case-insensitive storage)
            headers_dict = {}
            for key, value in response.headers.items():
                headers_dict[key] = value
            result['headers'] = headers_dict

            # Extract server information
            result['server'] = self._extract_server_info(response.headers)

            # Detect technologies
            result['technologies'] = self._detect_technologies(response.headers, response.text[:5000] if hasattr(response, 'text') else '')

            # Extract security headers
            result['security_headers'] = self._extract_security_headers(response.headers)

            # Check for redirects
            if response.history:
                result['redirect_url'] = response.url

            # Extract favicon
            favicon_url = self._extract_favicon(url, response)
            result['favicon_url'] = favicon_url

            # Download favicon locally if found and IOC ID provided
            if favicon_url and ioc_id:
                favicon_data = self._download_favicon(favicon_url, ioc_id)
                if favicon_data:
                    result['favicon_path'] = favicon_data['path']
                    result['favicon_sha256'] = favicon_data['sha256']

            # Extract SSL certificate info for HTTPS
            if url.lower().startswith('https://'):
                result['ssl_certificate'] = self._extract_ssl_certificate(url)

            return result

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout requesting URL: {url}")
            return {
                'url': url,
                'error': 'Request timeout',
                'status': 'error'
            }
        except requests.exceptions.SSLError as e:
            logger.error(f"SSL error for URL {url}: {e}")
            return {
                'url': url,
                'error': f'SSL error: {str(e)}',
                'status': 'error'
            }
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error for URL {url}: {e}")
            return {
                'url': url,
                'error': str(e),
                'status': 'error'
            }
        except Exception as e:
            logger.error(f"Error enriching URL {url}: {e}")
            return {
                'url': url,
                'error': str(e),
                'status': 'error'
            }

    def _extract_server_info(self, headers):
        """Extract server information from headers"""
        server_headers = [
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Generator',
            'X-Drupal-Cache',
            'X-Varnish',
            'X-Nginx',
            'X-Litespeed-Cache'
        ]

        server_info = []
        for header in server_headers:
            value = headers.get(header)
            if value:
                server_info.append(f"{header}: {value}")

        return '; '.join(server_info) if server_info else 'Unknown'

    def _detect_technologies(self, headers, content_sample):
        """Detect technologies from headers and content"""
        technologies = []

        # Check headers for technology indicators
        header_patterns = {
            'WordPress': ['X-Powered-By', 'wp-'],
            'Drupal': ['X-Drupal-Cache', 'X-Generator'],
            'Joomla': ['X-Content-Encoded-By'],
            'ASP.NET': ['X-AspNet-Version', 'X-AspNetMvc-Version'],
            'PHP': ['X-Powered-By'],
            'Nginx': ['Server', 'X-Nginx'],
            'Apache': ['Server'],
            'IIS': ['Server'],
            'Cloudflare': ['CF-Ray', 'Server'],
            'Varnish': ['X-Varnish'],
            'Express': ['X-Powered-By'],
            'Django': ['X-Frame-Options'],
            'Flask': ['Server'],
            'Rails': ['X-Powered-By'],
            'Tomcat': ['Server']
        }

        for tech, patterns in header_patterns.items():
            for pattern in patterns:
                for header_name, header_value in headers.items():
                    if pattern.lower() in header_name.lower() or pattern.lower() in str(header_value).lower():
                        if tech not in technologies:
                            technologies.append(tech)

        # Check specific header values
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            technologies.append('Nginx')
        if 'apache' in server:
            technologies.append('Apache')
        if 'iis' in server or 'microsoft' in server:
            technologies.append('IIS')
        if 'cloudflare' in server:
            technologies.append('Cloudflare')

        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append('PHP')
        if 'asp.net' in powered_by:
            technologies.append('ASP.NET')
        if 'express' in powered_by:
            technologies.append('Express.js')

        # Remove duplicates
        return list(set(technologies))

    def _extract_security_headers(self, headers):
        """Extract security-related headers"""
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not Set'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Not Set'),
            'Permissions-Policy': headers.get('Permissions-Policy', 'Not Set')
        }

        return security_headers

    def _extract_favicon(self, url, response):
        """Extract favicon URL from page"""
        try:
            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')

            # Look for favicon in link tags
            favicon_tags = [
                soup.find('link', rel='icon'),
                soup.find('link', rel='shortcut icon'),
                soup.find('link', rel='apple-touch-icon')
            ]

            for tag in favicon_tags:
                if tag and tag.get('href'):
                    favicon_url = tag['href']

                    # Handle relative URLs
                    if favicon_url.startswith('//'):
                        favicon_url = 'https:' + favicon_url
                    elif favicon_url.startswith('/'):
                        parsed_url = urlparse(url)
                        favicon_url = f"{parsed_url.scheme}://{parsed_url.netloc}{favicon_url}"
                    elif not favicon_url.startswith('http'):
                        parsed_url = urlparse(url)
                        favicon_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{favicon_url}"

                    return favicon_url

            # Default favicon location
            parsed_url = urlparse(url)
            default_favicon = f"{parsed_url.scheme}://{parsed_url.netloc}/favicon.ico"

            # Check if default favicon exists
            try:
                verify_ssl = not current_app.config.get('URL_ENRICHMENT_NO_SSL_CHECK', False)
                favicon_response = requests.head(default_favicon, timeout=5, verify=verify_ssl)
                if favicon_response.status_code == 200:
                    return default_favicon
            except:
                pass

            return None

        except Exception as e:
            logger.error(f"Error extracting favicon for {url}: {e}")
            return None

    def _download_favicon(self, favicon_url, ioc_id):
        """
        Download favicon to local cache directory and calculate SHA256 hash

        Args:
            favicon_url: URL of the favicon
            ioc_id: IOC ID to use as filename

        Returns:
            dict: {'path': str, 'sha256': str} or None if download failed
        """
        try:
            # Create cached/favicon directory if it doesn't exist
            cache_dir = Path('cached/favicon')
            cache_dir.mkdir(parents=True, exist_ok=True)

            # Get file extension from URL or content-type
            verify_ssl = not current_app.config.get('URL_ENRICHMENT_NO_SSL_CHECK', False)
            response = requests.get(favicon_url, timeout=10, verify=verify_ssl)

            if response.status_code != 200:
                logger.warning(f"Failed to download favicon: HTTP {response.status_code}")
                return None

            # Get file content
            file_content = response.content

            # Calculate SHA256 hash
            sha256_hash = hashlib.sha256(file_content).hexdigest()

            # Determine file extension
            content_type = response.headers.get('Content-Type', '')
            extension = '.ico'  # Default

            if 'png' in content_type:
                extension = '.png'
            elif 'jpeg' in content_type or 'jpg' in content_type:
                extension = '.jpg'
            elif 'gif' in content_type:
                extension = '.gif'
            elif 'svg' in content_type:
                extension = '.svg'
            elif 'webp' in content_type:
                extension = '.webp'
            elif favicon_url.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico')):
                # Try to get extension from URL
                extension = '.' + favicon_url.lower().split('.')[-1].split('?')[0]

            # Save favicon with IOC ID as filename
            filename = f"{ioc_id}{extension}"
            filepath = cache_dir / filename

            with open(filepath, 'wb') as f:
                f.write(file_content)

            logger.info(f"Downloaded favicon for IOC {ioc_id}: {filepath} (SHA256: {sha256_hash})")

            # Return both path and hash
            return {
                'path': str(filepath),
                'sha256': sha256_hash
            }

        except Exception as e:
            logger.error(f"Error downloading favicon from {favicon_url}: {e}")
            return None

    def _extract_ssl_certificate(self, url):
        """Extract SSL/TLS certificate information for HTTPS URLs"""
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            port = parsed_url.port or 443

            # Remove port from hostname if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            # Create SSL context
            context = ssl.create_default_context()

            # Disable verification if configured
            if current_app.config.get('URL_ENRICHMENT_NO_SSL_CHECK', False):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

                    if not cert:
                        return {}

                    # Extract certificate details
                    cert_info = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])],
                        'tls_version': ssock.version()
                    }

                    return cert_info

        except Exception as e:
            logger.error(f"Error extracting SSL certificate for {url}: {e}")
            return {}

    def _save_to_cache(self, url, enrichment_data):
        """Save enrichment data to cache"""
        try:
            cache_data = {
                'status_code': enrichment_data.get('status_code'),
                'server': enrichment_data.get('server'),
                'headers': json.dumps(enrichment_data.get('headers', {})),
                'technologies': json.dumps(enrichment_data.get('technologies', [])),
                'security_headers': json.dumps(enrichment_data.get('security_headers', {})),
                'redirect_url': enrichment_data.get('redirect_url'),
                'response_time': enrichment_data.get('response_time'),
                'content_type': enrichment_data.get('content_type'),
                'favicon_url': enrichment_data.get('favicon_url'),
                'favicon_path': enrichment_data.get('favicon_path'),
                'favicon_sha256': enrichment_data.get('favicon_sha256'),
                'ssl_certificate': json.dumps(enrichment_data.get('ssl_certificate', {}))
            }

            cache_entry = URLEnrichmentCache.create_cache_entry(
                url=url,
                enrichment_data=cache_data,
                cache_days=self.cache_days
            )

            db.session.add(cache_entry)
            db.session.commit()
            logger.info(f"Cached enrichment data for URL: {url}")

        except Exception as e:
            logger.error(f"Error caching enrichment data for {url}: {e}")
            db.session.rollback()
