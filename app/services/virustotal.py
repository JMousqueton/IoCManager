"""
VirusTotal Service
Handles VirusTotal API v3 integration with caching
"""

import json
import time
import logging
from datetime import datetime, timedelta
import requests
from flask import current_app

from app import db
from app.models import VirusTotalCache


logger = logging.getLogger(__name__)


class VTService:
    """VirusTotal API v3 Service with caching"""

    API_BASE_URL = 'https://www.virustotal.com/api/v3'

    def __init__(self, api_key=None, cache_days=None, rate_limit=None):
        """
        Initialize VirusTotal service

        Args:
            api_key: VirusTotal API key (default: from config)
            cache_days: Number of days to cache results (default: from config)
            rate_limit: Requests per minute (default: from config)
        """
        self.api_key = api_key or current_app.config.get('VIRUSTOTAL_API_KEY')
        self.cache_days = cache_days or current_app.config.get('VIRUSTOTAL_CACHE_DAYS', 7)
        self.rate_limit = rate_limit or current_app.config.get('VIRUSTOTAL_RATE_LIMIT', 4)
        self.no_ssl_check = current_app.config.get('VIRUSTOTAL_NO_SSL_CHECK', False)

        # Rate limiting state
        self.last_request_time = None
        self.request_interval = 60.0 / self.rate_limit  # seconds between requests

    def get_hash_report(self, hash_value):
        """
        Get VirusTotal report for a file hash

        Args:
            hash_value: MD5, SHA1, or SHA256 hash

        Returns:
            dict: VirusTotal report data or None if not found/error
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return {
                'error': 'VirusTotal API key not configured',
                'status': 'error'
            }

        # Normalize hash
        hash_value = hash_value.lower().strip()

        # Determine hash type
        hash_type = self._get_hash_type(hash_value)
        if not hash_type:
            logger.error(f"Invalid hash format: {hash_value}")
            return {
                'error': 'Invalid hash format',
                'status': 'error'
            }

        # Check cache first
        cached_data = self._check_cache(hash_value)
        if cached_data:
            logger.info(f"Cache hit for hash: {hash_value[:16]}...")
            return cached_data

        # Cache miss - query API
        logger.info(f"Cache miss for hash: {hash_value[:16]}... - querying VirusTotal API")
        api_data = self._query_api(hash_value)

        # If successful, also fetch MITRE ATT&CK data
        if api_data and api_data.get('status') == 'success':
            mitre_data = self._get_mitre_attack_trees(hash_value)
            if mitre_data:
                api_data['mitre_attack'] = mitre_data

        # Cache the response (even errors, to avoid repeated API calls)
        if api_data:
            self._cache_response(hash_value, hash_type, api_data)

        return api_data

    def get_url_report(self, url):
        """
        Get VirusTotal report for a URL

        Args:
            url: URL to scan

        Returns:
            dict: VirusTotal report data or None if not found/error
        """
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return {
                'error': 'VirusTotal API key not configured',
                'status': 'error'
            }

        # Normalize URL
        url = url.strip()

        # Rate limiting
        self._rate_limit_wait()

        # URL needs to be base64 encoded (URL-safe, no padding)
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')

        # API endpoint
        api_url = f"{self.API_BASE_URL}/urls/{url_id}"

        # Headers
        headers = {
            'x-apikey': self.api_key,
            'Accept': 'application/json'
        }

        try:
            logger.debug(f"Querying VirusTotal URL API: {api_url}")

            # Disable SSL verification if configured
            verify_ssl = not self.no_ssl_check

            if self.no_ssl_check:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = requests.get(api_url, headers=headers, timeout=30, verify=verify_ssl)

            # Update rate limit timestamp
            self.last_request_time = time.time()

            # Handle different status codes
            if response.status_code == 200:
                data = response.json()
                return self._parse_vt_url_response(data)

            elif response.status_code == 404:
                logger.info(f"URL not found in VirusTotal: {url[:50]}...")
                return {
                    'status': 'not_found',
                    'message': 'URL not found in VirusTotal database'
                }

            elif response.status_code == 429:
                logger.warning("VirusTotal API rate limit exceeded")
                return {
                    'status': 'rate_limited',
                    'error': 'API rate limit exceeded - please try again later'
                }

            elif response.status_code == 401:
                logger.error("VirusTotal API authentication failed")
                return {
                    'status': 'error',
                    'error': 'Invalid API key'
                }

            else:
                logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return {
                    'status': 'error',
                    'error': f'API error: {response.status_code}'
                }

        except requests.exceptions.Timeout:
            logger.error("VirusTotal API request timeout")
            return {
                'status': 'error',
                'error': 'Request timeout'
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API request failed: {e}")
            return {
                'status': 'error',
                'error': f'Request failed: {str(e)}'
            }

    def _get_hash_type(self, hash_value):
        """
        Determine hash type from length

        Args:
            hash_value: Hash string

        Returns:
            str: 'MD5', 'SHA1', 'SHA256', or None
        """
        length = len(hash_value)
        if length == 32:
            return 'MD5'
        elif length == 40:
            return 'SHA1'
        elif length == 64:
            return 'SHA256'
        return None

    def _check_cache(self, hash_value):
        """
        Check if hash report is in cache and not expired

        Args:
            hash_value: Hash to check

        Returns:
            dict: Cached report data or None
        """
        try:
            cache_entry = VirusTotalCache.query.filter_by(hash_value=hash_value).first()

            if cache_entry:
                # Check if expired
                if cache_entry.is_expired():
                    logger.info(f"Cache entry expired for {hash_value[:16]}...")
                    db.session.delete(cache_entry)
                    db.session.commit()
                    return None

                # Parse and return cached data
                try:
                    data = json.loads(cache_entry.response_data)
                    data['cached'] = True
                    data['cached_at'] = cache_entry.cached_at.isoformat()
                    return data
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON in cache for {hash_value[:16]}...")
                    db.session.delete(cache_entry)
                    db.session.commit()
                    return None

        except Exception as e:
            logger.error(f"Error checking cache: {e}")

        return None

    def _query_api(self, hash_value):
        """
        Query VirusTotal API v3 for hash report

        Args:
            hash_value: Hash to query

        Returns:
            dict: API response data
        """
        # Rate limiting
        self._rate_limit_wait()

        # API endpoint
        url = f"{self.API_BASE_URL}/files/{hash_value}"

        # Headers
        headers = {
            'x-apikey': self.api_key,
            'Accept': 'application/json'
        }

        try:
            logger.debug(f"Querying VirusTotal API: {url}")

            # Disable SSL verification if configured
            verify_ssl = not self.no_ssl_check
            logger.info(f"SSL verification: no_ssl_check={self.no_ssl_check}, verify_ssl={verify_ssl}")

            if self.no_ssl_check:
                logger.warning("SSL certificate verification is disabled for VirusTotal API")
                # Suppress SSL warnings
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = requests.get(url, headers=headers, timeout=30, verify=verify_ssl)

            # Update rate limit timestamp
            self.last_request_time = time.time()

            # Handle different status codes
            if response.status_code == 200:
                data = response.json()
                return self._parse_vt_response(data)

            elif response.status_code == 404:
                logger.info(f"Hash not found in VirusTotal: {hash_value[:16]}...")
                return {
                    'status': 'not_found',
                    'message': 'Hash not found in VirusTotal database'
                }

            elif response.status_code == 429:
                logger.warning("VirusTotal API rate limit exceeded")
                return {
                    'status': 'rate_limited',
                    'error': 'API rate limit exceeded - please try again later'
                }

            elif response.status_code == 401:
                logger.error("VirusTotal API authentication failed")
                return {
                    'status': 'error',
                    'error': 'Invalid API key'
                }

            else:
                logger.error(f"VirusTotal API error: {response.status_code} - {response.text}")
                return {
                    'status': 'error',
                    'error': f'API error: {response.status_code}'
                }

        except requests.exceptions.Timeout:
            logger.error("VirusTotal API request timeout")
            return {
                'status': 'error',
                'error': 'Request timeout'
            }

        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API request failed: {e}")
            return {
                'status': 'error',
                'error': f'Request failed: {str(e)}'
            }

    def _get_mitre_attack_trees(self, hash_value):
        """
        Get MITRE ATT&CK trees for a file hash

        Args:
            hash_value: Hash to query

        Returns:
            dict: MITRE ATT&CK data with tactics and techniques, or None
        """
        # Rate limiting
        self._rate_limit_wait()

        # API endpoint
        url = f"{self.API_BASE_URL}/files/{hash_value}/behaviour_mitre_trees"

        # Headers
        headers = {
            'x-apikey': self.api_key,
            'Accept': 'application/json'
        }

        try:
            logger.debug(f"Querying VirusTotal MITRE ATT&CK endpoint: {url}")

            # Disable SSL verification if configured
            verify_ssl = not self.no_ssl_check

            if self.no_ssl_check:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = requests.get(url, headers=headers, timeout=30, verify=verify_ssl)

            # Update rate limit timestamp
            self.last_request_time = time.time()

            # Handle different status codes
            if response.status_code == 200:
                data = response.json()
                return self._parse_mitre_trees(data)

            elif response.status_code == 404:
                logger.info(f"MITRE ATT&CK data not found for hash: {hash_value[:16]}...")
                return None

            elif response.status_code == 403:
                logger.warning("MITRE ATT&CK endpoint requires Premium API access")
                return None

            else:
                logger.error(f"MITRE ATT&CK API error: {response.status_code}")
                return None

        except requests.exceptions.Timeout:
            logger.error("MITRE ATT&CK API request timeout")
            return None

        except requests.exceptions.RequestException as e:
            logger.error(f"MITRE ATT&CK API request failed: {e}")
            return None

    def _parse_mitre_trees(self, data):
        """
        Parse MITRE ATT&CK trees response

        Args:
            data: Raw MITRE trees API response

        Returns:
            dict: Parsed tactics and techniques
        """
        try:
            parsed = {
                'tactics': [],
                'techniques': []
            }

            # The response structure is: {"data": {...}}
            trees_data = data.get('data', {})

            # Look for tactics and techniques in the response
            # The structure may vary, so we'll handle different formats

            # Check for 'Attck' or 'tactics' key
            for key in trees_data.keys():
                sandbox_data = trees_data[key]

                if isinstance(sandbox_data, dict):
                    # Look for tactics
                    tactics = sandbox_data.get('tactics', [])
                    if isinstance(tactics, list):
                        for tactic_item in tactics:
                            if isinstance(tactic_item, dict):
                                tactic_name = tactic_item.get('name') or tactic_item.get('tactic')
                                tactic_id = tactic_item.get('id')

                                if tactic_name and tactic_name not in parsed['tactics']:
                                    parsed['tactics'].append(tactic_name)

                                # Get techniques within this tactic
                                techniques = tactic_item.get('techniques', [])
                                if isinstance(techniques, list):
                                    for tech in techniques:
                                        if isinstance(tech, dict):
                                            tech_id = tech.get('id')
                                            tech_name = tech.get('name')

                                            if tech_id and tech_name:
                                                # Avoid duplicates
                                                if not any(t['id'] == tech_id for t in parsed['techniques']):
                                                    parsed['techniques'].append({
                                                        'id': tech_id,
                                                        'name': tech_name,
                                                        'tactic': tactic_name or 'Unknown'
                                                    })

            # If we found any data, return it
            if parsed['tactics'] or parsed['techniques']:
                logger.info(f"Parsed {len(parsed['tactics'])} tactics and {len(parsed['techniques'])} techniques")
                return parsed

            return None

        except Exception as e:
            logger.error(f"Error parsing MITRE trees: {e}")
            return None

    def _parse_vt_response(self, data):
        """
        Parse VirusTotal API v3 response for file hashes

        Args:
            data: Raw API response

        Returns:
            dict: Parsed and simplified response
        """
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            results = attributes.get('last_analysis_results', {})

            # Extract key information
            parsed = {
                'status': 'success',
                'hash': {
                    'md5': attributes.get('md5'),
                    'sha1': attributes.get('sha1'),
                    'sha256': attributes.get('sha256')
                },
                'file_info': {
                    'size': attributes.get('size'),  # File size in bytes
                    'type': attributes.get('type_description'),
                    'magic': attributes.get('magic'),
                },
                'stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'failure': stats.get('failure', 0)
                },
                'total_engines': sum(stats.values()),
                'detection_rate': f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                'first_submission': self._format_timestamp(attributes.get('first_submission_date')),
                'last_analysis': self._format_timestamp(attributes.get('last_analysis_date')),
                'reputation': attributes.get('reputation', 0),
                'tags': attributes.get('tags', []),
                'names': attributes.get('names', []),
                'threat_classification': self._get_threat_classification(stats),
                'permalink': f"https://www.virustotal.com/gui/file/{attributes.get('sha256')}"
            }

            # Add top detections
            detections = []
            for engine, result in results.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    detections.append({
                        'engine': engine,
                        'category': result.get('category'),
                        'result': result.get('result')
                    })

            parsed['top_detections'] = sorted(detections, key=lambda x: x['engine'])[:10]

            # Note: MITRE ATT&CK data is now fetched from separate endpoint
            # and will be merged in get_hash_report() method

            return parsed

        except Exception as e:
            logger.error(f"Error parsing VT response: {e}")
            return {
                'status': 'error',
                'error': f'Failed to parse response: {str(e)}',
                'raw_data': data
            }

    def _parse_vt_url_response(self, data):
        """
        Parse VirusTotal API v3 response for URLs

        Args:
            data: Raw API response

        Returns:
            dict: Parsed and simplified response
        """
        try:
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            results = attributes.get('last_analysis_results', {})

            # Extract key information
            parsed = {
                'status': 'success',
                'url': attributes.get('url'),
                'final_url': attributes.get('last_final_url'),
                'title': attributes.get('title'),
                'stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'timeout': stats.get('timeout', 0)
                },
                'total_engines': sum(stats.values()),
                'detection_rate': f"{stats.get('malicious', 0)}/{sum(stats.values())}",
                'first_submission': self._format_timestamp(attributes.get('first_submission_date')),
                'last_analysis': self._format_timestamp(attributes.get('last_analysis_date')),
                'reputation': attributes.get('reputation', 0),
                'categories': attributes.get('categories', {}),
                'threat_classification': self._get_threat_classification(stats),
                'permalink': f"https://www.virustotal.com/gui/url/{data.get('data', {}).get('id')}"
            }

            # Add top detections
            detections = []
            for engine, result in results.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    detections.append({
                        'engine': engine,
                        'category': result.get('category'),
                        'result': result.get('result')
                    })

            parsed['top_detections'] = sorted(detections, key=lambda x: x['engine'])[:10]

            return parsed

        except Exception as e:
            logger.error(f"Error parsing VT URL response: {e}")
            return {
                'status': 'error',
                'error': f'Failed to parse response: {str(e)}',
                'raw_data': data
            }

    def _format_timestamp(self, timestamp):
        """
        Convert Unix timestamp to ISO format string

        Args:
            timestamp: Unix timestamp (integer or None)

        Returns:
            ISO format string or None
        """
        if timestamp:
            from datetime import datetime
            try:
                dt = datetime.fromtimestamp(timestamp)
                return dt.isoformat()
            except (ValueError, TypeError):
                return None
        return None

    def _get_threat_classification(self, stats):
        """
        Classify threat level based on detection stats

        Args:
            stats: Detection statistics

        Returns:
            str: Threat classification
        """
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total = sum(stats.values())

        if total == 0:
            return 'Unknown'

        detection_ratio = (malicious + suspicious) / total

        if malicious >= 5:
            return 'Malicious'
        elif malicious > 0 or suspicious >= 3:
            return 'Suspicious'
        elif detection_ratio == 0:
            return 'Clean'
        else:
            return 'Likely Clean'

    def _cache_response(self, hash_value, hash_type, response_data):
        """
        Cache VirusTotal response

        Args:
            hash_value: Hash that was queried
            hash_type: Type of hash (MD5, SHA1, SHA256)
            response_data: Response data to cache
        """
        try:
            # Convert response to JSON string
            response_json = json.dumps(response_data)

            # Create cache entry
            cache_entry = VirusTotalCache.create_cache_entry(
                hash_value=hash_value,
                hash_type=hash_type,
                response_data=response_json,
                cache_days=self.cache_days
            )

            # Save to database
            db.session.add(cache_entry)
            db.session.commit()

            logger.info(f"Cached VT response for {hash_value[:16]}... (expires in {self.cache_days} days)")

        except Exception as e:
            logger.error(f"Error caching VT response: {e}")
            db.session.rollback()

    def _rate_limit_wait(self):
        """Wait if necessary to respect rate limiting"""
        if self.last_request_time:
            elapsed = time.time() - self.last_request_time
            wait_time = self.request_interval - elapsed

            if wait_time > 0:
                logger.debug(f"Rate limiting: waiting {wait_time:.2f} seconds")
                time.sleep(wait_time)

    def clean_expired_cache(self):
        """Remove expired cache entries"""
        try:
            expired_count = VirusTotalCache.query.filter(
                VirusTotalCache.expires_at < datetime.utcnow()
            ).delete()

            db.session.commit()
            logger.info(f"Cleaned {expired_count} expired VT cache entries")
            return expired_count

        except Exception as e:
            logger.error(f"Error cleaning expired cache: {e}")
            db.session.rollback()
            return 0
