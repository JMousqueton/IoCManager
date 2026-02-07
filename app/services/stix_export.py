"""
STIX 2.1 Export Service
Converts IOCs to STIX 2.1 format for sharing via TAXII or other platforms
"""

import json
import uuid
from datetime import datetime


class STIXExporter:
    """Export IOCs to STIX 2.1 format"""

    def __init__(self):
        self.stix_version = "2.1"

    def export_ioc(self, ioc):
        """
        Export a single IOC to STIX 2.1 format

        Args:
            ioc: IOC model instance

        Returns:
            dict: STIX 2.1 bundle
        """
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": self.stix_version,
            "objects": []
        }

        # Create indicator object
        indicator = self._create_indicator(ioc)
        bundle["objects"].append(indicator)

        # If enrichment data exists, create related objects
        if ioc.enrichment_data:
            enrichment = ioc.get_enrichment()

            # Add malware object if detected as malicious
            if enrichment and self._is_malicious(enrichment):
                malware = self._create_malware_object(ioc, enrichment)
                if malware:
                    bundle["objects"].append(malware)

                    # Add relationship between indicator and malware
                    relationship = self._create_relationship(
                        indicator["id"],
                        malware["id"],
                        "indicates"
                    )
                    bundle["objects"].append(relationship)

        return bundle

    def export_iocs(self, iocs):
        """
        Export multiple IOCs to STIX 2.1 format

        Args:
            iocs: List of IOC model instances

        Returns:
            dict: STIX 2.1 bundle containing all IOCs
        """
        bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": self.stix_version,
            "objects": []
        }

        for ioc in iocs:
            indicator = self._create_indicator(ioc)
            bundle["objects"].append(indicator)

            # Add enrichment-based objects
            if ioc.enrichment_data:
                enrichment = ioc.get_enrichment()

                if enrichment and self._is_malicious(enrichment):
                    malware = self._create_malware_object(ioc, enrichment)
                    if malware:
                        bundle["objects"].append(malware)

                        relationship = self._create_relationship(
                            indicator["id"],
                            malware["id"],
                            "indicates"
                        )
                        bundle["objects"].append(relationship)

        return bundle

    def _create_indicator(self, ioc):
        """Create STIX indicator object from IOC"""

        # Map IOC type to STIX pattern
        pattern = self._create_stix_pattern(ioc)

        # Map TLP to marking definition
        tlp_marking = self._get_tlp_marking(ioc.tlp)

        indicator = {
            "type": "indicator",
            "spec_version": self.stix_version,
            "id": f"indicator--{uuid.uuid4()}",
            "created": ioc.created_at.isoformat() + "Z" if ioc.created_at else datetime.utcnow().isoformat() + "Z",
            "modified": ioc.updated_at.isoformat() + "Z" if ioc.updated_at else datetime.utcnow().isoformat() + "Z",
            "name": ioc.value[:100],  # Truncate if too long
            "description": ioc.description or f"{ioc.ioc_type.name} indicator",
            "indicator_types": self._get_indicator_types(ioc),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.created_at.isoformat() + "Z" if ioc.created_at else datetime.utcnow().isoformat() + "Z",
            "confidence": self._map_confidence(ioc.confidence)
        }

        # Add validity period if expiration is set
        if ioc.expires_at:
            indicator["valid_until"] = ioc.expires_at.isoformat() + "Z"

        # Add labels/tags
        if ioc.tags:
            indicator["labels"] = [tag.name for tag in ioc.tags]

        # Add TLP marking
        if tlp_marking:
            indicator["object_marking_refs"] = [tlp_marking]

        # Add external references (VirusTotal, URLScan, etc.)
        external_refs = self._get_external_references(ioc)
        if external_refs:
            indicator["external_references"] = external_refs

        return indicator

    def _create_stix_pattern(self, ioc):
        """Create STIX pattern from IOC value and type"""

        ioc_type = ioc.ioc_type.name
        value = ioc.value

        # Escape special characters in value
        value = value.replace("\\", "\\\\").replace("'", "\\'")

        pattern_map = {
            "IPv4": f"[ipv4-addr:value = '{value}']",
            "IPv6": f"[ipv6-addr:value = '{value}']",
            "Domain": f"[domain-name:value = '{value}']",
            "URL": f"[url:value = '{value}']",
            "Email": f"[email-addr:value = '{value}']",
            "MD5": f"[file:hashes.MD5 = '{value}']",
            "SHA1": f"[file:hashes.'SHA-1' = '{value}']",
            "SHA256": f"[file:hashes.'SHA-256' = '{value}']",
        }

        return pattern_map.get(ioc_type, f"[file:name = '{value}']")

    def _get_indicator_types(self, ioc):
        """Map IOC attributes to STIX indicator types"""
        types = []

        # Based on IOC type
        ioc_type = ioc.ioc_type.name
        if ioc_type in ["IPv4", "IPv6", "Domain", "URL"]:
            types.append("malicious-activity")
        elif ioc_type in ["MD5", "SHA1", "SHA256"]:
            types.append("file-hash-watchlist")
        elif ioc_type == "Email":
            types.append("phishing")

        # Based on enrichment
        if ioc.enrichment_data:
            enrichment = ioc.get_enrichment()
            if self._is_malicious(enrichment):
                if "malicious-activity" not in types:
                    types.append("malicious-activity")

        return types if types else ["anomalous-activity"]

    def _create_malware_object(self, ioc, enrichment):
        """Create STIX malware object from enrichment data"""

        malware_name = None
        malware_types = ["unknown"]

        # Extract malware info from enrichment
        if isinstance(enrichment, dict):
            # VirusTotal hash enrichment
            if "names" in enrichment and enrichment["names"]:
                malware_name = enrichment["names"][0]

            # Try to determine malware type from tags or threat classification
            if "tags" in enrichment:
                malware_types = self._map_malware_types(enrichment["tags"])

        if not malware_name:
            malware_name = f"Malware-{ioc.value[:16]}"

        malware = {
            "type": "malware",
            "spec_version": self.stix_version,
            "id": f"malware--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": malware_name,
            "is_family": False,
            "malware_types": malware_types
        }

        return malware

    def _create_relationship(self, source_ref, target_ref, relationship_type):
        """Create STIX relationship object"""
        return {
            "type": "relationship",
            "spec_version": self.stix_version,
            "id": f"relationship--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref
        }

    def _get_tlp_marking(self, tlp):
        """Map TLP level to STIX marking definition reference"""
        tlp_map = {
            "WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
        }
        return tlp_map.get(tlp)

    def _get_external_references(self, ioc):
        """Extract external references from enrichment data"""
        refs = []

        if not ioc.enrichment_data:
            return refs

        enrichment = ioc.get_enrichment()

        if isinstance(enrichment, dict):
            # VirusTotal reference
            if "permalink" in enrichment:
                refs.append({
                    "source_name": "VirusTotal",
                    "url": enrichment["permalink"],
                    "description": "VirusTotal analysis"
                })

            # URLScan reference
            if "urlscan" in enrichment and enrichment["urlscan"]:
                urlscan = enrichment["urlscan"]
                if "report_url" in urlscan:
                    refs.append({
                        "source_name": "URLScan.io",
                        "url": urlscan["report_url"],
                        "description": "URLScan.io analysis"
                    })

            # VirusTotal URL reference
            if "virustotal" in enrichment and enrichment["virustotal"]:
                vt = enrichment["virustotal"]
                if "permalink" in vt:
                    refs.append({
                        "source_name": "VirusTotal",
                        "url": vt["permalink"],
                        "description": "VirusTotal URL analysis"
                    })

        return refs

    def _is_malicious(self, enrichment):
        """Determine if enrichment indicates malicious activity"""
        if not enrichment or not isinstance(enrichment, dict):
            return False

        # Check VirusTotal stats
        if "stats" in enrichment:
            stats = enrichment["stats"]
            if stats.get("malicious", 0) > 5:
                return True

        # Check URLScan verdict
        if "verdicts" in enrichment:
            verdicts = enrichment["verdicts"]
            if verdicts.get("malicious", False):
                return True

        # Check threat classification
        if enrichment.get("threat_classification") in ["Malicious", "Suspicious"]:
            return True

        return False

    def _map_confidence(self, confidence):
        """Map IOC confidence to STIX confidence (0-100)"""
        if not confidence:
            return 50
        return min(100, max(0, confidence))

    def _map_malware_types(self, tags):
        """Map tags to STIX malware types"""
        malware_types = set()

        tag_map = {
            "trojan": "trojan",
            "ransomware": "ransomware",
            "worm": "worm",
            "rootkit": "rootkit",
            "backdoor": "backdoor",
            "spyware": "spyware",
            "adware": "adware",
            "downloader": "downloader",
            "dropper": "dropper",
            "exploit": "exploit-kit",
            "keylogger": "keylogger",
            "bot": "bot",
            "remote-access": "remote-access-trojan"
        }

        for tag in tags:
            tag_lower = tag.lower() if isinstance(tag, str) else str(tag).lower()
            for key, value in tag_map.items():
                if key in tag_lower:
                    malware_types.add(value)

        return list(malware_types) if malware_types else ["unknown"]
