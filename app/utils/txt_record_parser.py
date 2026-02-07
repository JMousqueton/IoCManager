"""
TXT Record Parser
Identifies brands/services from TXT record content
"""

def get_txt_record_brand(txt_record):
    """
    Identify brand/service from TXT record and return Font Awesome icon class

    Args:
        txt_record (str): TXT record content

    Returns:
        dict: {'brand': 'Brand Name', 'icon': 'fa-brands fa-icon', 'color': 'hex-color'}
    """
    record_lower = txt_record.lower()

    # Google
    if 'google' in record_lower or 'google-site-verification' in record_lower:
        return {'brand': 'Google', 'icon': 'fa-brands fa-google', 'color': '#4285F4'}

    # Microsoft
    if 'ms=' in record_lower or 'microsoft' in record_lower or 'outlook.com' in record_lower or 'office365' in record_lower:
        return {'brand': 'Microsoft', 'icon': 'fa-brands fa-microsoft', 'color': '#00A4EF'}

    # Apple
    if 'apple' in record_lower or 'apple-domain-verification' in record_lower:
        return {'brand': 'Apple', 'icon': 'fa-brands fa-apple', 'color': '#000000'}

    # Facebook / Meta
    if 'facebook' in record_lower or 'facebook-domain-verification' in record_lower or 'meta-domain-verification' in record_lower:
        return {'brand': 'Facebook', 'icon': 'fa-brands fa-facebook', 'color': '#1877F2'}

    # Atlassian
    if 'atlassian' in record_lower:
        return {'brand': 'Atlassian', 'icon': 'fa-brands fa-atlassian', 'color': '#0052CC'}

    # DocuSign
    if 'docusign' in record_lower:
        return {'brand': 'DocuSign', 'icon': 'fa-solid fa-file-signature', 'color': '#FFCC00'}

    # Jamf
    if 'jamf' in record_lower:
        return {'brand': 'Jamf', 'icon': 'fa-solid fa-mobile-screen', 'color': '#000000'}

    # OpenAI
    if 'openai' in record_lower:
        return {'brand': 'OpenAI', 'icon': 'fa-solid fa-brain', 'color': '#10A37F'}

    # KnowBe4
    if 'knowbe4' in record_lower:
        return {'brand': 'KnowBe4', 'icon': 'fa-solid fa-shield-halved', 'color': '#FF6B00'}

    # MongoDB
    if 'mongodb' in record_lower:
        return {'brand': 'MongoDB', 'icon': 'fa-solid fa-database', 'color': '#47A248'}

    # OneTrust
    if 'onetrust' in record_lower:
        return {'brand': 'OneTrust', 'icon': 'fa-solid fa-user-shield', 'color': '#0033A0'}

    # Cisco
    if 'cisco' in record_lower:
        return {'brand': 'Cisco', 'icon': 'fa-solid fa-network-wired', 'color': '#1BA0D7'}

    # Adobe
    if 'adobe' in record_lower:
        return {'brand': 'Adobe', 'icon': 'fa-solid fa-a', 'color': '#FF0000'}

    # Amazon / AWS
    if 'amazonses' in record_lower or 'aws' in record_lower or '_amazonses' in record_lower:
        return {'brand': 'Amazon AWS', 'icon': 'fa-brands fa-aws', 'color': '#FF9900'}

    # Salesforce
    if 'salesforce' in record_lower:
        return {'brand': 'Salesforce', 'icon': 'fa-brands fa-salesforce', 'color': '#00A1E0'}

    # Slack
    if 'slack' in record_lower:
        return {'brand': 'Slack', 'icon': 'fa-brands fa-slack', 'color': '#4A154B'}

    # Dropbox
    if 'dropbox' in record_lower:
        return {'brand': 'Dropbox', 'icon': 'fa-brands fa-dropbox', 'color': '#0061FF'}

    # GitHub
    if 'github' in record_lower or '_github-' in record_lower:
        return {'brand': 'GitHub', 'icon': 'fa-brands fa-github', 'color': '#181717'}

    # Zoom
    if 'zoom' in record_lower or 'zoominfo' in record_lower:
        return {'brand': 'Zoom', 'icon': 'fa-solid fa-video', 'color': '#2D8CFF'}

    # Zendesk
    if 'zendesk' in record_lower:
        return {'brand': 'Zendesk', 'icon': 'fa-solid fa-headset', 'color': '#03363D'}

    # SPF (email)
    if record_lower.startswith('v=spf1'):
        return {'brand': 'SPF Record', 'icon': 'fa-solid fa-envelope-circle-check', 'color': '#28A745'}

    # DKIM (email)
    if 'dkim' in record_lower or record_lower.startswith('v=dkim1'):
        return {'brand': 'DKIM', 'icon': 'fa-solid fa-key', 'color': '#17A2B8'}

    # DMARC (email)
    if record_lower.startswith('v=dmarc1'):
        return {'brand': 'DMARC', 'icon': 'fa-solid fa-shield-alt', 'color': '#FFC107'}

    # Default - generic verification
    if 'verification' in record_lower or 'verify' in record_lower:
        return {'brand': 'Verification', 'icon': 'fa-solid fa-circle-check', 'color': '#6C757D'}

    # Default - unknown/unrecognized TXT record
    return {'brand': 'Unknown', 'icon': 'fa-solid fa-circle-question', 'color': '#ADB5BD'}
