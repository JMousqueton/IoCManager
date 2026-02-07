"""
WHOIS Status Parser
Converts WHOIS domain status codes to human-readable format
"""

def parse_whois_status(status_string):
    """
    Parse WHOIS status code to human-readable format

    Args:
        status_string (str): Raw WHOIS status (e.g., "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited")

    Returns:
        str: Human-readable status (e.g., "Delete Prohibited")
    """
    if not status_string:
        return "Unknown"

    # Remove URLs and extra whitespace
    status = status_string.split()[0].lower()

    # Map common WHOIS status codes to human-readable names
    status_map = {
        # Client statuses (most common)
        'clientdeleteprohibited': 'Delete Prohibited',
        'clientrenewprohibited': 'Renew Prohibited',
        'clienttransferprohibited': 'Transfer Prohibited',
        'clientupdateprohibited': 'Update Prohibited',
        'clienthold': 'Client Hold',

        # Server statuses
        'serverdeleteprohibited': 'Delete Prohibited (Server)',
        'serverrenewprohibited': 'Renew Prohibited (Server)',
        'servertransferprohibited': 'Transfer Prohibited (Server)',
        'serverupdateprohibited': 'Update Prohibited (Server)',
        'serverhold': 'Server Hold',

        # Domain states
        'ok': 'Active',
        'active': 'Active',
        'inactive': 'Inactive',
        'locked': 'Locked',

        # Pending states
        'pendingdelete': 'Pending Delete',
        'pendingrestore': 'Pending Restore',
        'pendingtransfer': 'Pending Transfer',
        'pendingrenew': 'Pending Renew',
        'pendingupdate': 'Pending Update',
        'pendingcreate': 'Pending Create',

        # Redemption
        'redemptionperiod': 'Redemption Period',

        # Add/Renew period
        'addperiod': 'Add Period',
        'renewperiod': 'Renew Period',
        'transferperiod': 'Transfer Period',
        'autorenewperiod': 'Auto-Renew Period',
    }

    # Try to find a match
    readable_status = status_map.get(status)

    if readable_status:
        return readable_status

    # If no match, try to format the camelCase status
    # Convert from camelCase to Title Case with spaces
    import re

    # Remove 'client' or 'server' prefix
    formatted = re.sub(r'^(client|server)', '', status, flags=re.IGNORECASE)

    # Insert spaces before capital letters
    formatted = re.sub(r'([a-z])([A-Z])', r'\1 \2', formatted)

    # Capitalize first letter of each word
    formatted = formatted.title()

    return formatted if formatted else status_string
