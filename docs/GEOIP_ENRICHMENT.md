# GeoIP Enrichment for IPv4/IPv6 IOCs

This document explains how to use the GeoIP enrichment service to add geolocation data to IP address IOCs.

## Overview

The GeoIP enrichment service uses MaxMind GeoLite2 databases to enrich IPv4 and IPv6 addresses with:
- Country information
- City information
- Geographic coordinates (latitude/longitude)
- Subdivision (state/region) information
- Postal code
- Time zone
- Continent information

## Prerequisites

1. **Install maxminddb library:**
   ```bash
   source venv/bin/activate
   pip install maxminddb
   ```

2. **Download MaxMind databases:**
   ```bash
   python scripts/download_asn_db.py
   # Select option 4 to download all databases
   ```

   This will download:
   - `data/GeoLite2-City.mmdb` (City-level geolocation)
   - `data/GeoLite2-Country.mmdb` (Country-level geolocation)

## Usage in Python Code

### Basic Usage

```python
from app.services.geoip import get_geoip_service

# Get the service instance
geoip = get_geoip_service()

# Check if service is available
if geoip.is_available():
    # Enrich an IPv4 address
    result = geoip.enrich_ipv4("8.8.8.8")

    if result:
        # Get human-readable summary
        summary = geoip.get_summary(result)
        print(f"Location: {summary}")

        # Access specific data
        print(f"Country: {result['country']['name']}")
        print(f"City: {result['city']['name']}")
        print(f"Coordinates: {result['location']['latitude']}, {result['location']['longitude']}")
```

### Enriching IOC on Creation

```python
from app.services.geoip import get_geoip_service
from app.models.ioc import IOC

# When creating an IPv4 IOC
ioc = IOC(
    value="8.8.8.8",
    ioc_type_id=1,  # IPv4 type
    # ... other fields
)

# Enrich the IOC
geoip = get_geoip_service()
if geoip.is_available():
    enrichment_data = geoip.enrich_ipv4(ioc.value)

    if enrichment_data:
        # Store enrichment data in notes or description
        summary = geoip.get_summary(enrichment_data)
        ioc.notes = f"GeoIP: {summary}\n\n{ioc.notes or ''}"

        # Or store as JSON in a custom field (if you have one)
        # ioc.enrichment_data = json.dumps(enrichment_data)
```

### Enrichment Data Structure

The enrichment returns a dictionary with the following structure:

```python
{
    "ip": "8.8.8.8",
    "country": {
        "iso_code": "US",
        "name": "United States",
        "geoname_id": 6252001
    },
    "city": {
        "name": "Mountain View",
        "geoname_id": 5375480
    },
    "location": {
        "latitude": 37.386,
        "longitude": -122.0838,
        "accuracy_radius": 1000,
        "time_zone": "America/Los_Angeles"
    },
    "postal": {
        "code": "94035"
    },
    "subdivisions": [
        {
            "iso_code": "CA",
            "name": "California",
            "geoname_id": 5332921
        }
    ],
    "continent": {
        "code": "NA",
        "name": "North America",
        "geoname_id": 6255149
    },
    "source": "GeoLite2-City"
}
```

## Integration Examples

### 1. Enrich on IOC View

```python
@ioc_bp.route('/<int:id>')
@login_required
def detail(id):
    ioc = IOC.query.get_or_404(id)

    # Enrich IPv4/IPv6 addresses on display
    enrichment = None
    if ioc.ioc_type.name in ['IPv4', 'IPv6']:
        geoip = get_geoip_service()
        if geoip.is_available():
            enrichment = geoip.enrich_ipv4(ioc.value)

    return render_template('ioc/detail.html',
                         ioc=ioc,
                         geoip_data=enrichment)
```

### 2. Bulk Enrichment

```python
from app.services.geoip import get_geoip_service

def enrich_all_ip_iocs():
    """Enrich all IPv4/IPv6 IOCs with geolocation data"""
    geoip = get_geoip_service()

    if not geoip.is_available():
        print("GeoIP service not available")
        return

    # Get all IP IOCs
    ip_types = ['IPv4', 'IPv6']
    iocs = IOC.query.join(IOCType).filter(IOCType.name.in_(ip_types)).all()

    enriched = 0
    for ioc in iocs:
        result = geoip.enrich_ipv4(ioc.value)
        if result:
            summary = geoip.get_summary(result)
            ioc.notes = f"GeoIP: {summary}\n\n{ioc.notes or ''}"
            enriched += 1

    db.session.commit()
    print(f"Enriched {enriched} IOCs")
```

### 3. API Endpoint for Enrichment

```python
@ioc_bp.route('/enrich/<int:id>', methods=['POST'])
@login_required
def enrich(id):
    """Enrich an IOC with GeoIP data"""
    ioc = IOC.query.get_or_404(id)

    if ioc.ioc_type.name not in ['IPv4', 'IPv6']:
        return jsonify({'error': 'Only IPv4/IPv6 IOCs can be enriched'}), 400

    geoip = get_geoip_service()
    if not geoip.is_available():
        return jsonify({'error': 'GeoIP service not available'}), 503

    enrichment = geoip.enrich_ipv4(ioc.value)

    if enrichment:
        return jsonify({
            'success': True,
            'data': enrichment,
            'summary': geoip.get_summary(enrichment)
        })
    else:
        return jsonify({'error': 'No geolocation data found'}), 404
```

## Testing

Run the test script to verify the enrichment service:

```bash
python test_geoip_enrichment.py
```

## Database Updates

To keep your GeoIP databases up-to-date, re-run the download script monthly:

```bash
python scripts/download_asn_db.py --license-key YOUR_KEY
# Select option 4 to update all databases
```

## Performance Notes

- The MaxMind databases are loaded into memory once when the service is initialized
- Lookups are very fast (microseconds per query)
- The City database is ~60MB and Country is ~9MB
- For production use, consider implementing a caching layer for frequently looked-up IPs

## Error Handling

The service handles errors gracefully:
- Returns `None` if databases are not available
- Returns `None` if IP address is not found (e.g., private IPs)
- Prints warnings for database loading errors

## License

This uses MaxMind GeoLite2 data, which requires a free license key.
Register at: https://www.maxmind.com/en/geolite2/signup
