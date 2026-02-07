"""
GeoIP Enrichment Service
Enriches IPv4/IPv6 addresses with geolocation data using MaxMind databases
"""

import os
import csv
import ipaddress
from pathlib import Path
from typing import Optional, Dict, Any, List

try:
    import maxminddb
    MAXMINDDB_AVAILABLE = True
except ImportError:
    MAXMINDDB_AVAILABLE = False


class GeoIPService:
    """Service for enriching IP addresses with geolocation data"""

    def __init__(self, data_dir: str = None):
        """
        Initialize GeoIP service

        Args:
            data_dir: Directory containing MaxMind MMDB files (default: ./data)
        """
        if data_dir is None:
            # Get the base directory of the project
            basedir = Path(__file__).parent.parent.parent
            data_dir = basedir / 'data'
        else:
            data_dir = Path(data_dir)

        self.data_dir = data_dir
        self.city_db = None
        self.country_db = None
        self.asn_data = []

        # Load databases if available
        self._load_databases()
        self._load_asn_csv()

    def _load_databases(self):
        """Load MaxMind databases"""
        if not MAXMINDDB_AVAILABLE:
            print("⚠ maxminddb library not installed. Run: pip install maxminddb")
            return

        # Load City database
        city_db_path = self.data_dir / 'GeoLite2-City.mmdb'
        if city_db_path.exists():
            try:
                self.city_db = maxminddb.open_database(str(city_db_path))
                print(f"✓ Loaded City database: {city_db_path}")
            except Exception as e:
                print(f"⚠ Error loading City database: {e}")

        # Load Country database
        country_db_path = self.data_dir / 'GeoLite2-Country.mmdb'
        if country_db_path.exists():
            try:
                self.country_db = maxminddb.open_database(str(country_db_path))
                print(f"✓ Loaded Country database: {country_db_path}")
            except Exception as e:
                print(f"⚠ Error loading Country database: {e}")

    def _load_asn_csv(self):
        """Load ASN data from MaxMind CSV file"""
        asn_csv_path = self.data_dir / 'GeoLite2-ASN-Blocks-IPv4.csv'
        if asn_csv_path.exists():
            try:
                with open(asn_csv_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        try:
                            network = ipaddress.ip_network(row['network'])
                            self.asn_data.append({
                                'network': network,
                                'asn': row['autonomous_system_number'],
                                'org': row['autonomous_system_organization']
                            })
                        except:
                            continue
                print(f"✓ Loaded ASN database: {asn_csv_path} ({len(self.asn_data)} entries)")
            except Exception as e:
                print(f"⚠ Error loading ASN database: {e}")

    def is_available(self) -> bool:
        """Check if GeoIP service is available"""
        return MAXMINDDB_AVAILABLE and (self.city_db is not None or self.country_db is not None)

    def enrich_ipv4(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Enrich IPv4 address with geolocation data

        Args:
            ip_address: IPv4 address to enrich

        Returns:
            Dictionary with geolocation data or None if not available
        """
        if not self.is_available():
            return None

        result = {
            'ip': ip_address,
            'country': {},
            'city': {},
            'location': {},
            'postal': {},
            'subdivisions': [],
            'continent': {}
        }

        # Try City database first (includes country data)
        if self.city_db:
            try:
                data = self.city_db.get(ip_address)
                if data:
                    result['country'] = self._extract_country(data)
                    result['city'] = self._extract_city(data)
                    result['location'] = self._extract_location(data)
                    result['postal'] = self._extract_postal(data)
                    result['subdivisions'] = self._extract_subdivisions(data)
                    result['continent'] = self._extract_continent(data)
                    result['source'] = 'GeoLite2-City'
                    return result
            except Exception as e:
                print(f"⚠ Error querying City database: {e}")

        # Fallback to Country database
        if self.country_db:
            try:
                data = self.country_db.get(ip_address)
                if data:
                    result['country'] = self._extract_country(data)
                    result['continent'] = self._extract_continent(data)
                    result['source'] = 'GeoLite2-Country'
                    return result
            except Exception as e:
                print(f"⚠ Error querying Country database: {e}")

        return None

    def enrich_ipv6(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Enrich IPv6 address with geolocation data

        Args:
            ip_address: IPv6 address to enrich

        Returns:
            Dictionary with geolocation data or None if not available
        """
        # MaxMind databases support both IPv4 and IPv6
        return self.enrich_ipv4(ip_address)

    def enrich_asn(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """
        Enrich IP address with ASN information using MaxMind CSV

        Args:
            ip_address: IP address to enrich

        Returns:
            Dictionary with ASN data or None if not available
        """
        if not self.asn_data:
            return None

        try:
            ip_obj = ipaddress.ip_address(ip_address)

            # Skip private/reserved IP addresses
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return None

            # Search for matching network
            for entry in self.asn_data:
                if ip_obj in entry['network']:
                    asn_data = {
                        'asn': entry['asn'],
                        'asn_description': entry['org'],
                        'network': {
                            'cidr': str(entry['network']),
                        }
                    }
                    return asn_data

            return None

        except Exception as e:
            # Silently fail for ASN lookups - they're optional enrichment
            return None

    def _extract_country(self, data: dict) -> dict:
        """Extract country information from MaxMind data"""
        country = {}
        if 'country' in data:
            country_data = data['country']
            country['iso_code'] = country_data.get('iso_code', '')
            country['name'] = country_data.get('names', {}).get('en', '')
            country['geoname_id'] = country_data.get('geoname_id')
        return country

    def _extract_city(self, data: dict) -> dict:
        """Extract city information from MaxMind data"""
        city = {}
        if 'city' in data:
            city_data = data['city']
            city['name'] = city_data.get('names', {}).get('en', '')
            city['geoname_id'] = city_data.get('geoname_id')
        return city

    def _extract_location(self, data: dict) -> dict:
        """Extract location coordinates from MaxMind data"""
        location = {}
        if 'location' in data:
            loc_data = data['location']
            location['latitude'] = loc_data.get('latitude')
            location['longitude'] = loc_data.get('longitude')
            location['accuracy_radius'] = loc_data.get('accuracy_radius')
            location['time_zone'] = loc_data.get('time_zone', '')
        return location

    def _extract_postal(self, data: dict) -> dict:
        """Extract postal code information from MaxMind data"""
        postal = {}
        if 'postal' in data:
            postal_data = data['postal']
            postal['code'] = postal_data.get('code', '')
        return postal

    def _extract_subdivisions(self, data: dict) -> list:
        """Extract subdivision (state/region) information from MaxMind data"""
        subdivisions = []
        if 'subdivisions' in data:
            for subdivision in data['subdivisions']:
                subdivisions.append({
                    'iso_code': subdivision.get('iso_code', ''),
                    'name': subdivision.get('names', {}).get('en', ''),
                    'geoname_id': subdivision.get('geoname_id')
                })
        return subdivisions

    def _extract_continent(self, data: dict) -> dict:
        """Extract continent information from MaxMind data"""
        continent = {}
        if 'continent' in data:
            continent_data = data['continent']
            continent['code'] = continent_data.get('code', '')
            continent['name'] = continent_data.get('names', {}).get('en', '')
            continent['geoname_id'] = continent_data.get('geoname_id')
        return continent

    def get_summary(self, enrichment_data: dict) -> str:
        """
        Get a human-readable summary of enrichment data

        Args:
            enrichment_data: Enrichment data dictionary

        Returns:
            Human-readable summary string
        """
        if not enrichment_data:
            return "No geolocation data available"

        parts = []

        # City, Subdivision, Country
        city_name = enrichment_data.get('city', {}).get('name')
        if city_name:
            parts.append(city_name)

        subdivisions = enrichment_data.get('subdivisions', [])
        if subdivisions and subdivisions[0].get('name'):
            parts.append(subdivisions[0]['name'])

        country_name = enrichment_data.get('country', {}).get('name')
        if country_name:
            parts.append(country_name)

        location = enrichment_data.get('location', {})
        if location.get('latitude') and location.get('longitude'):
            parts.append(f"({location['latitude']:.4f}, {location['longitude']:.4f})")

        return ', '.join(parts) if parts else "Location data incomplete"

    def close(self):
        """Close database connections"""
        if self.city_db:
            self.city_db.close()
        if self.country_db:
            self.country_db.close()


# Singleton instance
_geoip_service = None


def get_geoip_service() -> GeoIPService:
    """Get singleton GeoIP service instance"""
    global _geoip_service
    if _geoip_service is None:
        _geoip_service = GeoIPService()
    return _geoip_service
