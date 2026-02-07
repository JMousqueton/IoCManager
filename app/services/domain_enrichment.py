"""
Domain Enrichment Service
Handles WHOIS, DNS lookups, and certificate transparency with caching
"""

import json
import logging
import socket
import requests
from datetime import datetime, timedelta
from flask import current_app

from app import db
from app.models import DomainEnrichmentCache

logger = logging.getLogger(__name__)


class DomainEnrichmentService:
    """Domain Enrichment Service with caching"""

    def __init__(self, cache_days=None):
        """
        Initialize Domain Enrichment service

        Args:
            cache_days: Number of days to cache results (default: from config)
        """
        self.cache_days = cache_days or current_app.config.get('DOMAIN_ENRICHMENT_CACHE_DAYS', 30)

    def enrich_domain(self, domain):
        """
        Get enrichment data for a domain

        Args:
            domain: Domain name to enrich

        Returns:
            dict: Enrichment data including WHOIS, MX, TXT, NS, A records
        """
        # Normalize domain
        domain = domain.lower().strip()

        # Check cache first
        cached_data = self._check_cache(domain)
        if cached_data:
            logger.info(f"Cache hit for domain: {domain}")
            return cached_data

        # Cache miss - perform enrichment
        logger.info(f"Cache miss for domain: {domain} - performing enrichment")
        enrichment_data = self._perform_enrichment(domain)

        # Cache the results
        if enrichment_data and enrichment_data.get('status') != 'error':
            self._save_to_cache(domain, enrichment_data)

        return enrichment_data

    def _check_cache(self, domain):
        """Check if domain enrichment is cached and not expired"""
        try:
            cache_entry = DomainEnrichmentCache.query.filter_by(domain=domain).first()

            if cache_entry:
                if cache_entry.is_expired():
                    logger.info(f"Cache entry expired for domain: {domain}")
                    db.session.delete(cache_entry)
                    db.session.commit()
                    return None

                # Return cached data
                return {
                    'domain': cache_entry.domain,
                    'whois': json.loads(cache_entry.whois_data) if cache_entry.whois_data else {},
                    'mx_records': json.loads(cache_entry.mx_records) if cache_entry.mx_records else [],
                    'txt_records': json.loads(cache_entry.txt_records) if cache_entry.txt_records else [],
                    'ns_records': json.loads(cache_entry.ns_records) if cache_entry.ns_records else [],
                    'a_records': json.loads(cache_entry.a_records) if cache_entry.a_records else [],
                    'aaaa_records': json.loads(cache_entry.aaaa_records) if cache_entry.aaaa_records else [],
                    'certificates': json.loads(cache_entry.certificates) if cache_entry.certificates else [],
                    'registration_date': cache_entry.registration_date.isoformat() if cache_entry.registration_date else None,
                    'expiration_date': cache_entry.expiration_date.isoformat() if cache_entry.expiration_date else None,
                    'registrar': cache_entry.registrar,
                    'cached_at': cache_entry.cached_at.isoformat(),
                    'status': 'success'
                }

            return None

        except Exception as e:
            logger.error(f"Error checking cache for domain {domain}: {e}")
            return None

    def _perform_enrichment(self, domain):
        """Perform actual domain enrichment"""
        try:
            result = {
                'domain': domain,
                'whois': {},
                'mx_records': [],
                'txt_records': [],
                'ns_records': [],
                'a_records': [],
                'aaaa_records': [],
                'certificates': [],
                'registration_date': None,
                'expiration_date': None,
                'registrar': None,
                'status': 'success'
            }

            # Get DNS records
            result['mx_records'] = self._get_mx_records(domain)
            result['txt_records'] = self._get_txt_records(domain)
            result['ns_records'] = self._get_ns_records(domain)
            result['a_records'] = self._get_a_records(domain)
            result['aaaa_records'] = self._get_aaaa_records(domain)

            # Get SSL/TLS certificates from CT logs
            result['certificates'] = self._get_certificates(domain)

            # Get WHOIS data
            whois_data = self._get_whois_data(domain)
            if whois_data:
                result['whois'] = whois_data
                result['registration_date'] = whois_data.get('creation_date')
                result['expiration_date'] = whois_data.get('expiration_date')
                result['registrar'] = whois_data.get('registrar')

            return result

        except Exception as e:
            logger.error(f"Error enriching domain {domain}: {e}")
            return {
                'domain': domain,
                'error': str(e),
                'status': 'error'
            }

    def _get_mx_records(self, domain):
        """Get MX records for domain"""
        try:
            import dns.resolver
            records = []
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                records.append({
                    'priority': rdata.preference,
                    'host': str(rdata.exchange).rstrip('.')
                })
            return sorted(records, key=lambda x: x['priority'])
        except dns.resolver.NXDOMAIN:
            logger.warning(f"Domain does not exist: {domain}")
            return []
        except dns.resolver.NoAnswer:
            logger.info(f"No MX records for domain: {domain}")
            return []
        except Exception as e:
            logger.error(f"Error getting MX records for {domain}: {e}")
            return []

    def _get_txt_records(self, domain):
        """Get TXT records for domain"""
        try:
            import dns.resolver
            records = []
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_value = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                records.append(txt_value)
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception as e:
            logger.error(f"Error getting TXT records for {domain}: {e}")
            return []

    def _get_ns_records(self, domain):
        """Get NS records for domain"""
        try:
            import dns.resolver
            records = []
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                records.append(str(rdata).rstrip('.'))
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception as e:
            logger.error(f"Error getting NS records for {domain}: {e}")
            return []

    def _get_a_records(self, domain):
        """Get A records for domain"""
        try:
            import dns.resolver
            records = []
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                records.append(str(rdata))
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception as e:
            logger.error(f"Error getting A records for {domain}: {e}")
            return []

    def _get_aaaa_records(self, domain):
        """Get AAAA records for domain"""
        try:
            import dns.resolver
            records = []
            answers = dns.resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                records.append(str(rdata))
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception as e:
            logger.error(f"Error getting AAAA records for {domain}: {e}")
            return []

    def _get_certificates(self, domain):
        """Get SSL/TLS certificates from crt.sh (Certificate Transparency logs)"""
        try:
            # Query crt.sh API
            url = f"https://crt.sh/?q={domain}&exclude=expired&deduplicate=Y&output=json"

            # Log the request
            logger.info(f"Requesting certificates from: {url}")

            # Check if SSL verification should be disabled
            verify_ssl = not current_app.config.get('DOMAIN_ENRICHMENT_NO_SSL_CHECK', False)
            logger.info(f"SSL verification: {verify_ssl}")

            response = requests.get(url, timeout=10, verify=verify_ssl)
            logger.info(f"Response status: {response.status_code}")

            if response.status_code != 200:
                logger.warning(f"crt.sh returned status {response.status_code} for {domain}")
                return []

            certs_data = response.json()

            # Process and filter certificates
            unique_certs = {}
            current_time = datetime.utcnow()

            for cert in certs_data:
                # Parse dates
                not_after = None
                if cert.get('not_after'):
                    try:
                        not_after = datetime.strptime(cert['not_after'], '%Y-%m-%dT%H:%M:%S')
                    except:
                        continue

                # Skip expired certificates
                if not_after and not_after < current_time:
                    continue

                not_before = None
                if cert.get('not_before'):
                    try:
                        not_before = datetime.strptime(cert['not_before'], '%Y-%m-%dT%H:%M:%S')
                    except:
                        pass

                # Use serial_number as unique identifier to avoid duplicates
                serial = cert.get('serial_number')
                if not serial:
                    continue

                # Keep only the most recent entry per serial number
                if serial not in unique_certs or (not_before and unique_certs[serial]['not_before'] < not_before):
                    unique_certs[serial] = {
                        'issuer': cert.get('issuer_name', 'Unknown'),
                        'common_name': cert.get('common_name', cert.get('name_value', 'Unknown')),
                        'not_before': not_before.isoformat() if not_before else None,
                        'not_after': not_after.isoformat() if not_after else None,
                        'serial_number': serial
                    }

            # Convert to list and sort by not_after date (most recent first)
            certs_list = list(unique_certs.values())
            certs_list.sort(key=lambda x: x['not_after'] if x['not_after'] else '', reverse=True)

            # Limit to 20 most recent certificates
            return certs_list[:20]

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout querying crt.sh for {domain}")
            return []
        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying crt.sh for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing certificates for {domain}: {e}")
            return []

    def _get_whois_data(self, domain):
        """Get WHOIS data for domain"""
        try:
            import whois
            w = whois.whois(domain)

            # Parse dates
            creation_date = None
            expiration_date = None
            updated_date = None

            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0].isoformat() if w.creation_date[0] else None
                elif isinstance(w.creation_date, datetime):
                    creation_date = w.creation_date.isoformat()

            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    expiration_date = w.expiration_date[0].isoformat() if w.expiration_date[0] else None
                elif isinstance(w.expiration_date, datetime):
                    expiration_date = w.expiration_date.isoformat()

            if w.updated_date:
                if isinstance(w.updated_date, list):
                    updated_date = w.updated_date[0].isoformat() if w.updated_date[0] else None
                elif isinstance(w.updated_date, datetime):
                    updated_date = w.updated_date.isoformat()

            # Get registrar
            registrar = None
            if w.registrar:
                registrar = w.registrar if isinstance(w.registrar, str) else w.registrar[0]

            # Get name servers
            name_servers = []
            if w.name_servers:
                name_servers = [ns.lower() for ns in w.name_servers] if isinstance(w.name_servers, list) else [w.name_servers.lower()]

            # Get emails
            emails = []
            if w.emails:
                emails = list(w.emails) if isinstance(w.emails, list) else [w.emails]

            return {
                'domain_name': w.domain_name if isinstance(w.domain_name, str) else (w.domain_name[0] if w.domain_name else None),
                'registrar': registrar,
                'creation_date': creation_date,
                'expiration_date': expiration_date,
                'updated_date': updated_date,
                'name_servers': name_servers,
                'status': w.status if isinstance(w.status, list) else [w.status] if w.status else [],
                'emails': emails,
                'org': w.org,
                'country': w.country
            }

        except Exception as e:
            logger.error(f"Error getting WHOIS data for {domain}: {e}")
            return {}

    def _save_to_cache(self, domain, enrichment_data):
        """Save enrichment data to cache"""
        try:
            # Convert datetime strings back to datetime objects for the cache
            registration_date = None
            expiration_date = None

            if enrichment_data.get('registration_date'):
                try:
                    registration_date = datetime.fromisoformat(enrichment_data['registration_date'])
                except:
                    pass

            if enrichment_data.get('expiration_date'):
                try:
                    expiration_date = datetime.fromisoformat(enrichment_data['expiration_date'])
                except:
                    pass

            cache_data = {
                'whois_data': json.dumps(enrichment_data.get('whois', {})),
                'mx_records': json.dumps(enrichment_data.get('mx_records', [])),
                'txt_records': json.dumps(enrichment_data.get('txt_records', [])),
                'ns_records': json.dumps(enrichment_data.get('ns_records', [])),
                'a_records': json.dumps(enrichment_data.get('a_records', [])),
                'aaaa_records': json.dumps(enrichment_data.get('aaaa_records', [])),
                'certificates': json.dumps(enrichment_data.get('certificates', [])),
                'registration_date': registration_date,
                'expiration_date': expiration_date,
                'registrar': enrichment_data.get('registrar')
            }

            cache_entry = DomainEnrichmentCache.create_cache_entry(
                domain=domain,
                enrichment_data=cache_data,
                cache_days=self.cache_days
            )

            db.session.add(cache_entry)
            db.session.commit()
            logger.info(f"Cached enrichment data for domain: {domain}")

        except Exception as e:
            logger.error(f"Error caching enrichment data for {domain}: {e}")
            db.session.rollback()
