#!/usr/bin/env python3
"""
GeoIP Database Download Script
Downloads MaxMind GeoLite2 databases (ASN, Country, City) for IP enrichment
"""

import os
import sys
import gzip
import shutil
import tarfile
import requests
import argparse
import urllib3
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def download_geolite2_asn(account_id=None, license_key=None, verify_ssl=True):
    """Download MaxMind GeoLite2 ASN database (CSV format)"""
    result = download_geolite2_database('GeoLite2-ASN-CSV', account_id, license_key, verify_ssl)
    # Files are now in data directory, result returns the data_dir
    return result


def download_geolite2_database(edition_id, account_id=None, license_key=None, verify_ssl=True):
    """
    Generic function to download any MaxMind GeoLite2 database

    Args:
        edition_id: Database edition (e.g., 'GeoLite2-Country', 'GeoLite2-City', 'GeoLite2-ASN-CSV')
        account_id: MaxMind account ID (required since January 2023)
        license_key: MaxMind license key
        verify_ssl: Whether to verify SSL certificates (default: True)

    Returns:
        Path to extracted directory or None on failure
    """
    print("\n" + "="*60)
    print(f"MAXMIND {edition_id.upper()} DATABASE SETUP")
    print("="*60)

    if not verify_ssl:
        print("\n⚠ SSL certificate verification is disabled")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Get account ID and license key
    if not account_id:
        account_id = os.getenv('MAXMIND_ACCOUNT_ID', '').strip()

    if not license_key:
        license_key = os.getenv('MAXMIND_LICENSE_KEY', '').strip()

    if (not account_id or account_id == 'your-maxmind-account-id-here' or
            not license_key or license_key == 'your-maxmind-license-key-here'):
        print("\nMaxMind requires an Account ID and License Key to download GeoLite2 databases.")
        print("Sign up or log in to get your credentials:")
        print("https://www.maxmind.com/en/geolite2/signup")
        print("\nYou can set them in .env file:")
        print("  MAXMIND_ACCOUNT_ID=your-account-id-here")
        print("  MAXMIND_LICENSE_KEY=your-license-key-here\n")

        if not account_id or account_id == 'your-maxmind-account-id-here':
            account_id = input("Enter your MaxMind Account ID (or 'skip' to skip download): ").strip()
            if account_id.lower() == 'skip':
                print(f"\n⚠ Skipping {edition_id} download")
                return None

        if not license_key or license_key == 'your-maxmind-license-key-here':
            license_key = input("Enter your MaxMind License Key: ").strip()
            if not license_key:
                print(f"\n⚠ Skipping {edition_id} download")
                return None

    # Create data directory
    data_dir = Path('data')
    data_dir.mkdir(exist_ok=True)

    # Determine file extension based on edition
    suffix = 'zip' if 'CSV' in edition_id else 'tar.gz'
    url = f"https://download.maxmind.com/geoip/databases/{edition_id}/download?suffix={suffix}"

    print(f"\n1. Downloading {edition_id}...")

    try:
        response = requests.get(url, stream=True, timeout=60, verify=verify_ssl,
                                auth=(account_id, license_key))
        response.raise_for_status()

        # Save file
        file_path = data_dir / f'{edition_id}.{suffix}'
        with open(file_path, 'wb') as f:
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    print(f"\r  Progress: {percent:.1f}%", end='', flush=True)
        print()  # New line after progress

        print(f"✓ Downloaded to {file_path}")

        # Extract archive
        print("\n2. Extracting archive...")
        if suffix == 'zip':
            import zipfile
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(data_dir)
        else:  # tar.gz
            with tarfile.open(file_path, 'r:gz') as tar_ref:
                tar_ref.extractall(data_dir)

        print("✓ Extracted successfully")

        # Find the extracted directory
        extracted_dir = None
        prefix = edition_id.replace('-CSV', '')
        for item in data_dir.iterdir():
            if item.is_dir() and item.name.startswith(prefix):
                extracted_dir = item
                break

        if not extracted_dir:
            print("✗ Could not find extracted directory")
            file_path.unlink()
            return None

        print(f"✓ Found extracted directory: {extracted_dir}")

        # Move important files to data directory
        print("\n3. Moving files to data directory...")

        moved_files = []
        if 'CSV' in edition_id:
            # For CSV editions, move all CSV files
            for csv_file in extracted_dir.glob('*.csv'):
                dest_file = data_dir / csv_file.name
                if dest_file.exists():
                    dest_file.unlink()
                shutil.move(str(csv_file), str(dest_file))
                moved_files.append(dest_file)
                print(f"  ✓ Moved {csv_file.name}")
        else:
            # For MMDB editions, move the .mmdb file
            for mmdb_file in extracted_dir.glob('*.mmdb'):
                dest_file = data_dir / mmdb_file.name
                if dest_file.exists():
                    dest_file.unlink()
                shutil.move(str(mmdb_file), str(dest_file))
                moved_files.append(dest_file)
                print(f"  ✓ Moved {mmdb_file.name}")

        # Clean up: remove extracted directory and archive
        shutil.rmtree(extracted_dir)
        file_path.unlink()
        print(f"\n✓ Cleaned up temporary files and directories")

        if moved_files:
            print(f"\n✓ Files available in {data_dir}:")
            for f in moved_files:
                print(f"  • {f.name}")

        return data_dir

    except requests.exceptions.RequestException as e:
        print(f"\n✗ Error downloading database: {e}")
        print("\nPossible issues:")
        print("  - Invalid Account ID or License Key")
        print("  - Network connection problem")
        print("  - MaxMind service unavailable")
        print("  - Verify credentials at: https://www.maxmind.com/en/account")
        return None


def download_geolite2_country(account_id=None, license_key=None, verify_ssl=True):
    """Download MaxMind GeoLite2 Country database"""
    return download_geolite2_database('GeoLite2-Country', account_id, license_key, verify_ssl)


def download_geolite2_city(account_id=None, license_key=None, verify_ssl=True):
    """Download MaxMind GeoLite2 City database"""
    return download_geolite2_database('GeoLite2-City', account_id, license_key, verify_ssl)

def create_dummy_db():
    """Create a dummy database file for development"""
    data_dir = Path('data')
    data_dir.mkdir(exist_ok=True)

    db_path = data_dir / 'ipasn.dat'

    print("\n" + "="*60)
    print("CREATING DUMMY ASN DATABASE (DEVELOPMENT ONLY)")
    print("="*60)

    print(f"\n⚠ Creating empty database file at {db_path}")
    print("This is for development purposes only.")
    print("The application will fall back to ipwhois for real AS lookups.")

    # Create empty file
    db_path.touch()

    print(f"\n✓ Created {db_path}")


def main():
    """Main function"""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Download and setup GeoIP databases (ASN, Country, City) for IOC Manager'
    )
    parser.add_argument(
        '--NoSSLCheck',
        action='store_true',
        help='Disable SSL certificate verification (use with caution)'
    )
    parser.add_argument(
        '--account-id',
        type=str,
        help='MaxMind account ID (skip interactive prompt)'
    )
    parser.add_argument(
        '--license-key',
        type=str,
        help='MaxMind license key (skip interactive prompt)'
    )
    parser.add_argument(
        '--auto',
        action='store_true',
        help='Automatic mode: download all databases using credentials from .env (option 4)'
    )
    args = parser.parse_args()

    print("\n" + "="*60)
    print("IOC MANAGER - ASN DATABASE SETUP")
    print("="*60)

    print("\nThis script helps you set up GeoIP databases for enriching")
    print("IP address indicators with geographic and AS information.")

    verify_ssl = not args.NoSSLCheck

    # Auto mode: automatically download all databases
    if args.auto:
        print("\n🤖 AUTO MODE: Downloading all databases using .env configuration")
        choice = '4'
    else:
        print("\n\nOptions:")
        print("1. Download MaxMind GeoLite2 ASN (CSV format)")
        print("2. Download MaxMind GeoLite2 Country (MMDB format)")
        print("3. Download MaxMind GeoLite2 City (MMDB format)")
        print("4. Download ALL databases (ASN, Country, City)")
        print("5. Create dummy ASN database (development only)")
        print("6. Skip (you can run this script later)")

        choice = input("\nEnter your choice (1-6): ").strip()

    if choice == '1':
        print("\n" + "="*60)
        print("DOWNLOADING ASN DATABASE")
        print("="*60)
        source_dir = download_geolite2_asn(
            account_id=args.account_id,
            license_key=args.license_key,
            verify_ssl=verify_ssl
        )

    elif choice == '2':
        print("\n" + "="*60)
        print("DOWNLOADING COUNTRY DATABASE")
        print("="*60)
        download_geolite2_country(
            account_id=args.account_id,
            license_key=args.license_key,
            verify_ssl=verify_ssl
        )

    elif choice == '3':
        print("\n" + "="*60)
        print("DOWNLOADING CITY DATABASE")
        print("="*60)
        download_geolite2_city(
            account_id=args.account_id,
            license_key=args.license_key,
            verify_ssl=verify_ssl
        )

    elif choice == '4':
        print("\n" + "="*60)
        print("DOWNLOADING ALL DATABASES")
        print("="*60)

        # Get account ID and license key once if not provided
        account_id = args.account_id or os.getenv('MAXMIND_ACCOUNT_ID', '').strip()
        license_key = args.license_key or os.getenv('MAXMIND_LICENSE_KEY', '').strip()

        credentials_valid = (
            account_id and account_id != 'your-maxmind-account-id-here' and
            license_key and license_key != 'your-maxmind-license-key-here'
        )

        if not credentials_valid:
            if args.auto:
                print("\n✗ ERROR: No valid MaxMind credentials found in .env file")
                print("Please set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in .env")
                print("or use --account-id and --license-key arguments")
                sys.exit(1)

            print("\nMaxMind requires an Account ID and License Key to download GeoLite2 databases.")
            print("Sign up or log in at: https://www.maxmind.com/en/geolite2/signup")
            print("\nYou can set them in .env file:")
            print("  MAXMIND_ACCOUNT_ID=your-account-id-here")
            print("  MAXMIND_LICENSE_KEY=your-license-key-here\n")

            if not account_id or account_id == 'your-maxmind-account-id-here':
                account_id = input("Enter your MaxMind Account ID (or 'skip' to skip): ").strip()
                if account_id.lower() == 'skip':
                    print("\n⚠ Skipping database downloads")
                    account_id = None

            if account_id and (not license_key or license_key == 'your-maxmind-license-key-here'):
                license_key = input("Enter your MaxMind License Key: ").strip()
                if not license_key:
                    account_id = None
        else:
            print(f"\n✓ Using Account ID from .env: {account_id}")
            print(f"✓ Using License Key from .env: {license_key[:8]}...{license_key[-4:]}")

        if account_id and license_key:
            # Download ASN
            print("\n[1/3] ASN Database")
            asn_dir = download_geolite2_asn(
                account_id=account_id,
                license_key=license_key,
                verify_ssl=verify_ssl
            )

            # Download Country
            print("\n[2/3] Country Database")
            download_geolite2_country(
                account_id=account_id,
                license_key=license_key,
                verify_ssl=verify_ssl
            )

            # Download City
            print("\n[3/3] City Database")
            download_geolite2_city(
                account_id=account_id,
                license_key=license_key,
                verify_ssl=verify_ssl
            )

            if asn_dir:
                convert_to_pyasn_format(asn_dir)

    elif choice == '5':
        create_dummy_db()

    else:
        print("\n⚠ Skipping GeoIP database setup")
        print("You can run this script later: python scripts/download_asn_db.py")

    print("\n" + "="*60)
    print("SETUP COMPLETE")
    print("="*60)

    print("\nUsage Notes:")
    print("  • ASN Database: Used for AS number lookups (CSV format)")
    print("  • Country Database: Used for country-level geolocation (MMDB format)")
    print("  • City Database: Used for city-level geolocation (MMDB format)")
    print("\nThe application will fall back to ipwhois for real-time queries")
    print("if the local ASN database is unavailable.")
    print("\nFor MMDB databases, use the 'maxminddb' Python library:")
    print("  pip install maxminddb")
    print("\n")


if __name__ == '__main__':
    main()
