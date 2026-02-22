"""Hunting Query Generator Service

Generates ready-to-use threat hunting queries for:
- Splunk SPL
- KQL (Microsoft Sentinel / Defender XDR)
- Sigma (YAML)
- CrowdStrike Falcon FQL
"""

import re
from datetime import datetime


class HuntingQueryGenerator:
    """Generate hunting queries from IOC data for multiple SIEM/EDR platforms"""

    @staticmethod
    def generate_queries(ioc):
        """
        Generate hunting queries for all supported platforms.

        Returns:
            dict with keys: splunk, kql, sigma, crowdstrike
        """
        ioc_type = ioc.ioc_type.name
        value = ioc.value.strip()
        enrichment = ioc.get_enrichment()
        tags_str = ", ".join([t.name for t in ioc.tags]) if ioc.tags else ""
        date_str = datetime.utcnow().strftime('%Y-%m-%d')

        return {
            'splunk': HuntingQueryGenerator._splunk(ioc_type, value, ioc, enrichment),
            'kql': HuntingQueryGenerator._kql(ioc_type, value, ioc, enrichment),
            'sigma': HuntingQueryGenerator._sigma(ioc_type, value, ioc, enrichment, tags_str, date_str),
            'crowdstrike': HuntingQueryGenerator._crowdstrike(ioc_type, value, ioc, enrichment),
        }

    # ─── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_domain(url):
        """Extract domain from URL"""
        match = re.search(r'://([^/?#]+)', url)
        return match.group(1) if match else url

    @staticmethod
    def _get_hashes(ioc_type, value, enrichment):
        """Collect all available hash values from enrichment + IOC value"""
        hashes = {}
        if enrichment and enrichment.get('hash'):
            h = enrichment['hash']
            if h.get('md5'):    hashes['md5']    = h['md5'].lower()
            if h.get('sha1'):   hashes['sha1']   = h['sha1'].lower()
            if h.get('sha256'): hashes['sha256'] = h['sha256'].lower()
        if not hashes:
            v = value.lower()
            if ioc_type == 'MD5':    hashes['md5']    = v
            elif ioc_type == 'SHA1':   hashes['sha1']   = v
            elif ioc_type == 'SHA256': hashes['sha256'] = v
            else: hashes['hash'] = v
        return hashes

    @staticmethod
    def _sigma_level(ioc):
        """Map IOC severity to Sigma level"""
        mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'informational',
        }
        return mapping.get(str(ioc.severity).lower(), 'medium')

    # ─── Splunk SPL ───────────────────────────────────────────────────────────

    @staticmethod
    def _splunk(ioc_type, value, ioc, enrichment):

        if ioc_type in ['IPv4', 'IPv6']:
            return f'''| comment "IOC #{ioc.id} - Malicious IP: {value}"
index=* earliest=-30d
    ( src_ip="{value}" OR dest_ip="{value}"
      OR src="{value}" OR dst="{value}"
      OR dns.query="{value}" )
| table _time, host, sourcetype, src_ip, dest_ip, action, user
| sort - _time'''

        elif ioc_type == 'Domain':
            return f'''| comment "IOC #{ioc.id} - Malicious Domain: {value}"
index=* earliest=-30d
    ( dns.query="{value}" OR http.host="{value}"
      OR url="*{value}*" OR domain="{value}"
      OR query="{value}" OR cs-host="{value}" )
| table _time, host, sourcetype, src_ip, dest_ip, url, user
| sort - _time'''

        elif ioc_type == 'URL':
            domain = HuntingQueryGenerator._extract_domain(value)
            return f'''| comment "IOC #{ioc.id} - Malicious URL: {value[:60]}"
index=* earliest=-30d
    ( url="{value}" OR url="{value}*"
      OR http.host="{domain}" OR cs-uri-stem="{value}"
      OR cs-uri-stem="*{domain}*" )
| table _time, host, sourcetype, src_ip, url, http_method, status, user
| sort - _time'''

        elif ioc_type in ['MD5', 'SHA1', 'SHA256', 'SSDEEP']:
            hashes = HuntingQueryGenerator._get_hashes(ioc_type, value, enrichment)
            parts = []
            if hashes.get('md5'):    parts.append(f'MD5="{hashes["md5"]}"')
            if hashes.get('sha1'):   parts.append(f'SHA1="{hashes["sha1"]}"')
            if hashes.get('sha256'): parts.append(f'SHA256="{hashes["sha256"]}"')
            if not parts: parts = [f'file_hash="{value}"']
            cond = '\n      OR '.join(parts)
            return f'''| comment "IOC #{ioc.id} - Malicious Hash"
index=* earliest=-30d
    ( {cond} )
| table _time, host, sourcetype, process_name, file_name, file_hash, user
| sort - _time'''

        elif ioc_type == 'Email':
            return f'''| comment "IOC #{ioc.id} - Malicious Email: {value}"
index=* earliest=-30d sourcetype IN ("email", "smtp", "ms:o365:reporting:messagetrace")
    ( from="{value}" OR sender="{value}"
      OR recipient="{value}" OR to="{value}" )
| table _time, host, sourcetype, from, to, subject, action
| sort - _time'''

        else:
            return f'''| comment "IOC #{ioc.id} - {ioc_type}: {value[:60]}"
index=* earliest=-30d "{value}"
| table _time, host, sourcetype, _raw
| sort - _time'''

    # ─── KQL (Microsoft Sentinel / Defender XDR) ──────────────────────────────

    @staticmethod
    def _kql(ioc_type, value, ioc, enrichment):

        if ioc_type in ['IPv4', 'IPv6']:
            return f'''// IOC #{ioc.id} - Malicious IP: {value}
let ioc_ip = "{value}";
union DeviceNetworkEvents, CommonSecurityLog, AzureNetworkAnalytics_CL
| where TimeGenerated > ago(30d)
| where RemoteIP == ioc_ip
    or SourceIP == ioc_ip
    or DestinationIP == ioc_ip
| project TimeGenerated, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, ActionType, AccountName
| sort by TimeGenerated desc'''

        elif ioc_type == 'Domain':
            return f'''// IOC #{ioc.id} - Malicious Domain: {value}
let ioc_domain = "{value}";
union DeviceNetworkEvents, DnsEvents
| where TimeGenerated > ago(30d)
| where RemoteUrl contains ioc_domain
    or Name contains ioc_domain
    or QueryName contains ioc_domain
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, ActionType, AccountName
| sort by TimeGenerated desc'''

        elif ioc_type == 'URL':
            domain = HuntingQueryGenerator._extract_domain(value)
            return f'''// IOC #{ioc.id} - Malicious URL: {value[:60]}
let ioc_url = "{value}";
let ioc_domain = "{domain}";
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where RemoteUrl contains ioc_url
    or RemoteUrl contains ioc_domain
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP,
          InitiatingProcessFileName, ActionType, AccountName
| sort by TimeGenerated desc'''

        elif ioc_type in ['MD5', 'SHA1', 'SHA256', 'SSDEEP']:
            hashes = HuntingQueryGenerator._get_hashes(ioc_type, value, enrichment)
            parts = []
            if hashes.get('md5'):    parts.append(f'MD5 =~ "{hashes["md5"]}"')
            if hashes.get('sha1'):   parts.append(f'SHA1 =~ "{hashes["sha1"]}"')
            if hashes.get('sha256'): parts.append(f'SHA256 =~ "{hashes["sha256"]}"')
            if not parts: parts = [f'Hashes contains "{value}"']
            cond = '\n    or '.join(parts)
            return f'''// IOC #{ioc.id} - Malicious Hash
union DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents
| where TimeGenerated > ago(30d)
| where {cond}
| project TimeGenerated, DeviceName, FileName, FolderPath,
          MD5, SHA1, SHA256, ActionType, AccountName
| sort by TimeGenerated desc'''

        elif ioc_type == 'Email':
            return f'''// IOC #{ioc.id} - Malicious Email: {value}
let ioc_email = "{value}";
EmailEvents
| where TimeGenerated > ago(30d)
| where SenderFromAddress =~ ioc_email
    or RecipientEmailAddress =~ ioc_email
| project TimeGenerated, Subject, SenderFromAddress,
          RecipientEmailAddress, DeliveryAction, ThreatTypes
| sort by TimeGenerated desc'''

        else:
            return f'''// IOC #{ioc.id} - {ioc_type}: {value[:60]}
search "{value}"
| where TimeGenerated > ago(30d)
| project TimeGenerated, Type, _ResourceId, _ItemId
| sort by TimeGenerated desc'''

    # ─── Sigma ────────────────────────────────────────────────────────────────

    @staticmethod
    def _sigma(ioc_type, value, ioc, enrichment, tags_str, date_str):
        level = HuntingQueryGenerator._sigma_level(ioc)
        ioc_id = ioc.id

        if ioc_type in ['IPv4', 'IPv6']:
            return f'''title: Malicious IP Detection - IOC #{ioc_id}
id: ioc-manager-{ioc_id}-ip
status: experimental
description: Detects network activity involving malicious IP {value}
references:
    - 'IOC Manager #{ioc_id}'
author: IOC Manager
date: {date_str}
tags:
    - attack.command_and_control
    - attack.t1071
logsource:
    category: network_connection
detection:
    selection_dst:
        DestinationIp: '{value}'
    selection_src:
        SourceIp: '{value}'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: {level}'''

        elif ioc_type == 'Domain':
            return f'''title: Malicious Domain Detection - IOC #{ioc_id}
id: ioc-manager-{ioc_id}-domain
status: experimental
description: Detects DNS query or network connection to malicious domain {value}
references:
    - 'IOC Manager #{ioc_id}'
author: IOC Manager
date: {date_str}
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: dns
detection:
    selection:
        query|contains: '{value}'
    condition: selection
falsepositives:
    - Unknown
level: {level}'''

        elif ioc_type == 'URL':
            return f'''title: Malicious URL Detection - IOC #{ioc_id}
id: ioc-manager-{ioc_id}-url
status: experimental
description: Detects HTTP request to malicious URL {value[:60]}
references:
    - 'IOC Manager #{ioc_id}'
author: IOC Manager
date: {date_str}
tags:
    - attack.command_and_control
    - attack.t1071.001
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '{value}'
    condition: selection
falsepositives:
    - Unknown
level: {level}'''

        elif ioc_type in ['MD5', 'SHA1', 'SHA256', 'SSDEEP']:
            hashes = HuntingQueryGenerator._get_hashes(ioc_type, value, enrichment)
            hash_lines = []
            if hashes.get('sha256'): hash_lines.append(f"        - 'SHA256={hashes['sha256']}'")
            if hashes.get('sha1'):   hash_lines.append(f"        - 'SHA1={hashes['sha1']}'")
            if hashes.get('md5'):    hash_lines.append(f"        - 'MD5={hashes['md5']}'")
            if not hash_lines: hash_lines = [f"        - '{value}'"]
            detection_block = '\n'.join(hash_lines)
            return f'''title: Malicious File Hash Detection - IOC #{ioc_id}
id: ioc-manager-{ioc_id}-hash
status: experimental
description: Detects execution or presence of file with known malicious hash
references:
    - 'IOC Manager #{ioc_id}'
author: IOC Manager
date: {date_str}
tags:
    - attack.execution
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Hashes|contains:
{detection_block}
    condition: selection
falsepositives:
    - Unknown
level: {level}'''

        elif ioc_type == 'Email':
            return f'''title: Malicious Email Address Detection - IOC #{ioc_id}
id: ioc-manager-{ioc_id}-email
status: experimental
description: Detects email activity involving malicious address {value}
references:
    - 'IOC Manager #{ioc_id}'
author: IOC Manager
date: {date_str}
tags:
    - attack.initial_access
    - attack.t1566
logsource:
    product: office365
    service: exchange
detection:
    selection_sender:
        senderAddress|contains: '{value}'
    selection_recipient:
        recipientAddress|contains: '{value}'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: {level}'''

        else:
            return f'''title: IOC Detection - {ioc_type} #{ioc_id}
id: ioc-manager-{ioc_id}-generic
status: experimental
description: Detects activity related to {ioc_type} indicator {value[:60]}
references:
    - 'IOC Manager #{ioc_id}'
author: IOC Manager
date: {date_str}
logsource:
    category: generic
detection:
    keywords:
        - '{value}'
    condition: keywords
falsepositives:
    - Unknown
level: {level}'''

    # ─── CrowdStrike Falcon FQL ────────────────────────────────────────────────

    @staticmethod
    def _crowdstrike(ioc_type, value, ioc, enrichment):

        if ioc_type in ['IPv4', 'IPv6']:
            return f'''// IOC #{ioc.id} - Malicious IP: {value}
// CrowdStrike Falcon - Event Search (FQL) | Last 30 days

// Network connections:
#event_simpleName IN (NetworkConnectIP4, NetworkConnectIP6)
| RemoteAddressIP4="{value}"
| table #timestamp, ComputerName, UserName, RemoteAddressIP4, RemotePort, Protocol

// DNS lookups resolving to this IP:
#event_simpleName=DnsRequest
| IP="{value}"
| table #timestamp, ComputerName, UserName, DomainName, IP'''

        elif ioc_type == 'Domain':
            return f'''// IOC #{ioc.id} - Malicious Domain: {value}
// CrowdStrike Falcon - Event Search (FQL) | Last 30 days

// DNS queries:
#event_simpleName=DnsRequest
| DomainName="{value}"
| table #timestamp, ComputerName, UserName, DomainName, RequestType, IP

// HTTP connections:
#event_simpleName IN (NetworkConnectIP4, HttpRequest)
| HttpHost="{value}"
| table #timestamp, ComputerName, UserName, HttpHost, RemoteAddressIP4, RemotePort'''

        elif ioc_type == 'URL':
            domain = HuntingQueryGenerator._extract_domain(value)
            return f'''// IOC #{ioc.id} - Malicious URL: {value[:60]}
// CrowdStrike Falcon - Event Search (FQL) | Last 30 days

// HTTP requests:
#event_simpleName IN (NetworkConnectIP4, HttpRequest)
| HttpHost="{domain}"
| table #timestamp, ComputerName, UserName, HttpHost, HttpPath, RemoteAddressIP4

// DNS lookups:
#event_simpleName=DnsRequest
| DomainName="{domain}"
| table #timestamp, ComputerName, UserName, DomainName, IP'''

        elif ioc_type in ['MD5', 'SHA1', 'SHA256', 'SSDEEP']:
            hashes = HuntingQueryGenerator._get_hashes(ioc_type, value, enrichment)
            blocks = []
            if hashes.get('sha256'):
                blocks.append(
                    f'// SHA256:\n'
                    f'#event_simpleName IN (ProcessRollup2, SyntheticProcessRollup2, NewExecutableWritten)\n'
                    f'| SHA256HashData="{hashes["sha256"]}"\n'
                    f'| table #timestamp, ComputerName, UserName, FileName, FilePath, SHA256HashData'
                )
            if hashes.get('md5'):
                blocks.append(
                    f'// MD5:\n'
                    f'#event_simpleName IN (ProcessRollup2, SyntheticProcessRollup2)\n'
                    f'| MD5HashData="{hashes["md5"]}"\n'
                    f'| table #timestamp, ComputerName, UserName, FileName, FilePath, MD5HashData'
                )
            if hashes.get('sha1'):
                blocks.append(
                    f'// SHA1:\n'
                    f'#event_simpleName IN (ProcessRollup2, SyntheticProcessRollup2)\n'
                    f'| SHA1HashData="{hashes["sha1"]}"\n'
                    f'| table #timestamp, ComputerName, UserName, FileName, FilePath, SHA1HashData'
                )
            if not blocks:
                blocks.append(
                    f'#event_simpleName IN (ProcessRollup2, SyntheticProcessRollup2)\n'
                    f'| SHA256HashData="{value}"\n'
                    f'| table #timestamp, ComputerName, UserName, FileName, FilePath, SHA256HashData'
                )
            return (
                f'// IOC #{ioc.id} - Malicious Hash\n'
                f'// CrowdStrike Falcon - Event Search (FQL) | Last 30 days\n\n'
                + '\n\n'.join(blocks)
            )

        elif ioc_type == 'Email':
            return f'''// IOC #{ioc.id} - Malicious Email: {value}
// CrowdStrike Falcon - Event Search (FQL) | Last 30 days
// Requires Falcon for Email or Microsoft 365 integration

#event_simpleName=EmailActivity
| SenderEmailAddress="{value}"
| table #timestamp, ComputerName, SenderEmailAddress, RecipientEmailAddress, Subject, Action

// Identity Protection - suspicious logons:
#event_simpleName=UserLogon
| UserPrincipalName="{value}"
| table #timestamp, ComputerName, UserName, UserPrincipalName, LogonType'''

        else:
            return f'''// IOC #{ioc.id} - {ioc_type}: {value[:60]}
// CrowdStrike Falcon - Event Search (FQL) | Last 30 days

// Generic keyword search:
"{value}"
| table #timestamp, ComputerName, UserName, #event_simpleName'''
