"""
URLScan.io Service
Handles URLScan.io API integration with caching
"""

import json
import time
import logging
from datetime import datetime, timedelta
import requests
from flask import current_app

from app import db
from app.models import URLScanCache


logger = logging.getLogger(__name__)


class URLScanService:
    """URLScan.io API Service with caching"""

    API_BASE_URL = 'https://urlscan.io/api/v1'

    def __init__(self, api_key=None, cache_days=None, rate_limit=None):
        """
        Initialize URLScan service

        Args:
            api_key: URLScan.io API key (default: from config)
            cache_days: Number of days to cache results (default: from config)
            rate_limit: Requests per minute (default: from config)
        """
        self.api_key = api_key or current_app.config.get('URLSCAN_API_KEY')
        self.cache_days = cache_days or current_app.config.get('URLSCAN_CACHE_DAYS', 7)
        self.rate_limit = rate_limit or current_app.config.get('URLSCAN_RATE_LIMIT', 1)
        self.no_ssl_check = current_app.config.get('URLSCAN_NO_SSL_CHECK', False)

        # Rate limiting state
        self.last_request_time = None
        self.request_interval = 60.0 / self.rate_limit  # seconds between requests

    def get_url_report(self, url):
        """
        Get URLScan report for a URL

        Args:
            url: URL to scan

        Returns:
            dict: URLScan report data or None if not found/error
        """
        if not self.api_key:
            logger.warning("URLScan API key not configured")
            return {
                'error': 'URLScan API key not configured',
                'status': 'error'
            }

        # Normalize URL
        url = url.strip()

        # Check cache first
        cached_data = self._check_cache(url)
        if cached_data:
            logger.info(f"Cache hit for URL: {url[:50]}...")
            return cached_data

        # Cache miss - query API
        logger.info(f"Cache miss for URL: {url[:50]}... - querying URLScan API")
        api_data = self._query_api(url)

        # Cache the response (except pending status)
        if api_data and api_data.get('status') not in ['pending', 'error']:
            self._cache_response(url, api_data)

        return api_data

    def _check_cache(self, url):
        """
        Check if URL report is in cache and not expired

        Args:
            url: URL to check

        Returns:
            dict: Cached report data or None
        """
        try:
            cache_entry = URLScanCache.query.filter_by(url=url).first()

            if cache_entry:
                # Check if expired
                if cache_entry.is_expired():
                    logger.info(f"Cache entry expired for {url[:50]}...")
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
                    logger.error(f"Invalid JSON in cache for {url[:50]}...")
                    db.session.delete(cache_entry)
                    db.session.commit()
                    return None

        except Exception as e:
            logger.error(f"Error checking cache: {e}")

        return None

    def _query_api(self, url):
        """
        Query URLScan API for URL report

        Args:
            url: URL to scan

        Returns:
            dict: API response data
        """
        # URLScan.io requires submitting a scan and then retrieving results
        # First, try to search for existing scans
        search_result = self._search_url(url)

        if search_result and search_result.get('status') == 'success':
            return search_result

        # If no recent scan found, submit a new scan
        return self._submit_and_wait(url)

    def _search_url(self, url):
        """Search for existing scans of the URL"""
        # Rate limiting
        self._rate_limit_wait()

        search_url = f"{self.API_BASE_URL}/search/"
        params = {
            'q': f'page.url:"{url}"',
            'size': 1
        }
        headers = {
            'API-Key': self.api_key
        }

        try:
            verify_ssl = not self.no_ssl_check
            if self.no_ssl_check:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = requests.get(search_url, params=params, headers=headers, timeout=30, verify=verify_ssl)
            self.last_request_time = time.time()

            if response.status_code == 200:
                data = response.json()
                if data.get('results') and len(data['results']) > 0:
                    # Found existing scan - get the full result
                    scan_id = data['results'][0]['_id']
                    return self._get_result(scan_id)

            return None

        except Exception as e:
            logger.error(f"Error searching URLScan: {e}")
            return None

    def _submit_and_wait(self, url):
        """Submit URL for scanning and wait for results"""
        # Rate limiting
        self._rate_limit_wait()

        submit_url = f"{self.API_BASE_URL}/scan/"
        headers = {
            'API-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        data = {
            'url': url,
            'visibility': 'public'
        }

        try:
            verify_ssl = not self.no_ssl_check
            if self.no_ssl_check:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = requests.post(submit_url, json=data, headers=headers, timeout=30, verify=verify_ssl)
            self.last_request_time = time.time()

            if response.status_code == 200:
                submit_data = response.json()
                scan_id = submit_data.get('uuid')

                if scan_id:
                    # Wait for scan to complete with progressive retries
                    logger.info(f"Submitted scan {scan_id}, waiting for results...")

                    # Try multiple times with shorter waits (total ~12 seconds)
                    wait_times = [5, 4, 3]  # Check after 5s, then 4s, then 3s

                    for i, wait_time in enumerate(wait_times):
                        time.sleep(wait_time)
                        result = self._get_result(scan_id)

                        # If we got a result (not pending), return it
                        if result.get('status') != 'pending':
                            return result

                        # If this is the last retry, return pending status
                        if i == len(wait_times) - 1:
                            logger.info(f"Scan {scan_id} still pending after {sum(wait_times)}s")
                            return {
                                'status': 'pending',
                                'scan_id': scan_id,
                                'message': 'Scan is taking longer than expected. Try refreshing the page in a moment.'
                            }

                    return self._get_result(scan_id)

            elif response.status_code == 429:
                logger.warning("URLScan API rate limit exceeded")
                return {
                    'status': 'rate_limited',
                    'error': 'API rate limit exceeded - please try again later'
                }

            elif response.status_code == 401:
                logger.error("URLScan API authentication failed")
                return {
                    'status': 'error',
                    'error': 'Invalid API key'
                }

            else:
                logger.error(f"URLScan API error: {response.status_code} - {response.text}")
                return {
                    'status': 'error',
                    'error': f'API error: {response.status_code}'
                }

        except Exception as e:
            logger.error(f"Error submitting to URLScan: {e}")
            return {
                'status': 'error',
                'error': f'Request failed: {str(e)}'
            }

    def _get_result(self, scan_id):
        """Get scan results by UUID"""
        # Rate limiting
        self._rate_limit_wait()

        result_url = f"{self.API_BASE_URL}/result/{scan_id}/"
        headers = {
            'API-Key': self.api_key
        }

        try:
            verify_ssl = not self.no_ssl_check
            if self.no_ssl_check:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            response = requests.get(result_url, headers=headers, timeout=30, verify=verify_ssl)
            self.last_request_time = time.time()

            if response.status_code == 200:
                data = response.json()
                return self._parse_urlscan_response(data, scan_id)

            elif response.status_code == 404:
                logger.info(f"Scan result not ready yet: {scan_id}")
                return {
                    'status': 'pending',
                    'message': 'Scan in progress - try again in a moment'
                }

            else:
                logger.error(f"Error retrieving result: {response.status_code}")
                return {
                    'status': 'error',
                    'error': f'Error retrieving result: {response.status_code}'
                }

        except Exception as e:
            logger.error(f"Error getting URLScan result: {e}")
            return {
                'status': 'error',
                'error': f'Request failed: {str(e)}'
            }

    def _parse_urlscan_response(self, data, scan_id):
        """
        Parse URLScan API response

        Args:
            data: Raw API response
            scan_id: Scan UUID

        Returns:
            dict: Parsed and simplified response
        """
        try:
            page = data.get('page', {})
            task = data.get('task', {})
            stats = data.get('stats', {})
            verdicts = data.get('verdicts', {})

            parsed = {
                'status': 'success',
                'scan_id': scan_id,
                'url': task.get('url'),
                'domain': task.get('domain'),
                'ip': page.get('ip'),
                'asn': page.get('asn'),
                'country': page.get('country'),
                'server': page.get('server'),
                'title': page.get('title'),
                'screenshot': f"https://urlscan.io/screenshots/{scan_id}.png",
                'report_url': f"https://urlscan.io/result/{scan_id}/",
                'scan_time': task.get('time'),
                'verdicts': {
                    'overall': verdicts.get('overall', {}).get('score', 0),
                    'malicious': verdicts.get('overall', {}).get('malicious', False),
                    'categories': verdicts.get('overall', {}).get('categories', [])
                },
                'stats': {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'total_requests': stats.get('requests', 0),
                    'total_domains': stats.get('domains', 0),
                    'total_ips': stats.get('ips', 0)
                }
            }

            return parsed

        except Exception as e:
            logger.error(f"Error parsing URLScan response: {e}")
            return {
                'status': 'error',
                'error': f'Failed to parse response: {str(e)}',
                'raw_data': data
            }

    def _cache_response(self, url, response_data):
        """
        Cache URLScan response

        Args:
            url: URL that was scanned
            response_data: Response data to cache
        """
        try:
            # Convert response to JSON string
            response_json = json.dumps(response_data)

            # Create cache entry
            cache_entry = URLScanCache.create_cache_entry(
                url=url,
                response_data=response_json,
                cache_days=self.cache_days
            )

            # Save to database
            db.session.add(cache_entry)
            db.session.commit()

            logger.info(f"Cached URLScan response for {url[:50]}... (expires in {self.cache_days} days)")

        except Exception as e:
            logger.error(f"Error caching URLScan response: {e}")
            db.session.rollback()

    def _rate_limit_wait(self):
        """Wait if necessary to respect rate limiting"""
        if self.last_request_time:
            elapsed = time.time() - self.last_request_time
            wait_time = self.request_interval - elapsed

            if wait_time > 0:
                logger.debug(f"Rate limiting: waiting {wait_time:.2f} seconds")
                time.sleep(wait_time)
