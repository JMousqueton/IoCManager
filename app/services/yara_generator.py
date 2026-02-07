"""YARA Rule Generator Service"""

from datetime import datetime


class YaraGenerator:
    """Generate YARA rules from IOC data"""

    @staticmethod
    def generate_rule(ioc):
        """
        Generate YARA rule for an IOC

        Args:
            ioc: IOC object

        Returns:
            str: YARA rule content
        """
        ioc_type = ioc.ioc_type.name

        if ioc_type in ['SHA256', 'SHA1', 'MD5']:
            return YaraGenerator._generate_hash_rule(ioc)
        elif ioc_type in ['IPv4', 'IPv6']:
            return YaraGenerator._generate_ip_rule(ioc)
        elif ioc_type in ['Domain', 'URL']:
            return YaraGenerator._generate_network_rule(ioc)
        else:
            return YaraGenerator._generate_generic_rule(ioc)

    @staticmethod
    def _generate_hash_rule(ioc):
        """Generate YARA rule for hash-based IOC"""
        enrichment = ioc.get_enrichment()

        # Get all available hashes
        hashes = {}
        if enrichment and enrichment.get('hash'):
            hashes['md5'] = enrichment['hash'].get('md5')
            hashes['sha1'] = enrichment['hash'].get('sha1')
            hashes['sha256'] = enrichment['hash'].get('sha256')
        else:
            # Use the IOC value itself
            if ioc.ioc_type.name == 'MD5':
                hashes['md5'] = ioc.value.lower()
            elif ioc.ioc_type.name == 'SHA1':
                hashes['sha1'] = ioc.value.lower()
            elif ioc.ioc_type.name == 'SHA256':
                hashes['sha256'] = ioc.value.lower()

        # Build rule name (sanitize for YARA)
        rule_name = f"IOC_{ioc.id}_Hash_Detection"

        # Get file info from enrichment
        file_info = ""
        file_size = None
        if enrichment and enrichment.get('file_info'):
            file_size = enrichment['file_info'].get('size')
            file_type = enrichment['file_info'].get('type')
            if file_size:
                file_info += f"\n        filesize = \"{file_size} bytes\""
            if file_type:
                file_info += f"\n        filetype = \"{file_type}\""

        # Get tags
        tags_str = ", ".join([tag.name for tag in ioc.tags]) if ioc.tags else "malware"

        # Build hash metadata - include all available hashes
        hash_metadata = ""
        if hashes.get('md5'):
            hash_metadata += f'\n        md5 = "{hashes["md5"]}"'
        if hashes.get('sha1'):
            hash_metadata += f'\n        sha1 = "{hashes["sha1"]}"'
        if hashes.get('sha256'):
            hash_metadata += f'\n        sha256 = "{hashes["sha256"]}"'

        # Build condition - use priority: SHA256 > SHA1 > MD5
        hash_condition = None
        if hashes.get('sha256'):
            hash_condition = f'hash.sha256(0, filesize) == "{hashes["sha256"]}"'
        elif hashes.get('sha1'):
            hash_condition = f'hash.sha1(0, filesize) == "{hashes["sha1"]}"'
        elif hashes.get('md5'):
            hash_condition = f'hash.md5(0, filesize) == "{hashes["md5"]}"'
        else:
            hash_condition = "false"

        # Build final condition with filesize check if available
        if file_size:
            # Include filesize check for more precise detection
            condition = f"filesize == {file_size} and {hash_condition}"
        else:
            condition = hash_condition

        # Build threat classification
        threat_class = "Unknown"
        if enrichment and enrichment.get('threat_classification'):
            threat_class = enrichment['threat_classification']

        rule = f"""import "hash"

rule {rule_name}
{{
    meta:
        description = "Detects file with known malicious hash"
        ioc_id = "{ioc.id}"
        severity = "{ioc.severity}"
        tlp = "{ioc.tlp}"
        confidence = "{ioc.confidence}%"
        tags = "{tags_str}"
        threat_classification = "{threat_class}"
        source = "IOC Manager"
        created = "{datetime.utcnow().strftime('%Y-%m-%d')}"
        reference = "IOC #{ioc.id}"{hash_metadata}{file_info}

    condition:
        {condition}
}}
"""
        return rule

    @staticmethod
    def _generate_ip_rule(ioc):
        """Generate YARA rule for IP-based IOC"""
        rule_name = f"IOC_{ioc.id}_IP_Detection"
        ip_value = ioc.value

        # Get geo info
        enrichment = ioc.get_enrichment()
        geo_info = ""
        if enrichment:
            if enrichment.get('country'):
                geo_info += f"\n        country = \"{enrichment['country'].get('name', 'Unknown')}\""
            if enrichment.get('asn'):
                geo_info += f"\n        asn = \"{enrichment['asn'].get('number', 'Unknown')}\""
                geo_info += f"\n        as_org = \"{enrichment['asn'].get('organization', 'Unknown')}\""

        tags_str = ", ".join([tag.name for tag in ioc.tags]) if ioc.tags else "network"

        rule = f"""rule {rule_name}
{{
    meta:
        description = "Detects network traffic to/from malicious IP"
        ioc_id = "{ioc.id}"
        ip_address = "{ip_value}"
        severity = "{ioc.severity}"
        tlp = "{ioc.tlp}"
        confidence = "{ioc.confidence}%"
        tags = "{tags_str}"
        source = "IOC Manager"
        created = "{datetime.utcnow().strftime('%Y-%m-%d')}"{geo_info}

    strings:
        $ip = "{ip_value}" ascii wide

    condition:
        $ip
}}
"""
        return rule

    @staticmethod
    def _generate_network_rule(ioc):
        """Generate YARA rule for domain/URL-based IOC"""
        rule_name = f"IOC_{ioc.id}_Network_Detection"
        value = ioc.value

        # Extract domain from URL if needed
        domain = value
        if ioc.ioc_type.name == 'URL':
            import re
            match = re.search(r'://([^/]+)', value)
            if match:
                domain = match.group(1)

        tags_str = ", ".join([tag.name for tag in ioc.tags]) if ioc.tags else "network"

        rule = f"""rule {rule_name}
{{
    meta:
        description = "Detects malicious {ioc.ioc_type.name.lower()}"
        ioc_id = "{ioc.id}"
        {ioc.ioc_type.name.lower()} = "{value}"
        severity = "{ioc.severity}"
        tlp = "{ioc.tlp}"
        confidence = "{ioc.confidence}%"
        tags = "{tags_str}"
        source = "IOC Manager"
        created = "{datetime.utcnow().strftime('%Y-%m-%d')}"

    strings:
        $indicator = "{value}" ascii wide nocase
        $domain = "{domain}" ascii wide nocase

    condition:
        any of them
}}
"""
        return rule

    @staticmethod
    def _generate_generic_rule(ioc):
        """Generate generic YARA rule for other IOC types"""
        rule_name = f"IOC_{ioc.id}_Detection"
        value = ioc.value

        tags_str = ", ".join([tag.name for tag in ioc.tags]) if ioc.tags else "generic"

        rule = f"""rule {rule_name}
{{
    meta:
        description = "Detects {ioc.ioc_type.name} indicator"
        ioc_id = "{ioc.id}"
        ioc_type = "{ioc.ioc_type.name}"
        indicator = "{value}"
        severity = "{ioc.severity}"
        tlp = "{ioc.tlp}"
        confidence = "{ioc.confidence}%"
        tags = "{tags_str}"
        source = "IOC Manager"
        created = "{datetime.utcnow().strftime('%Y-%m-%d')}"

    strings:
        $indicator = "{value}" ascii wide

    condition:
        $indicator
}}
"""
        return rule
