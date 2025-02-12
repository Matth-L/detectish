import email
import re
import spf
import dns.resolver
from email import policy
from email.parser import BytesParser
from enum import Enum

class SPFStatus(Enum):
    """ 
    Enum class for the SPF status of an email.
    """
    VALID = "SPF valid: sender is authorized."
    INVALID = "SPF invalid: sender is not authorized."
    SOFT_WARNING = "SPF soft warning: sender is likely not authorized."
    NEUTRAL = "SPF neutral or unknown."
    NO_IP = "IP address not found."
    NO_SPF_RECORD = "No SPF record found for this domain."
    INVALID_DOMAIN = "Invalid domain or no DNS response."
    DNS_ERROR = "DNS error."
    SPF_ERROR = "Error during SPF verification."

def extract_email(address: str) -> str:
    """
    Extracts the email address from a From or Sender field.

    :param address: The address string to extract from.
    :return: The extracted email address.
    """

    # ex : From: "aw-confirm@ebay.com" <aw-confirm@ebay.com>
    # match between < and >
    adr = re.search(r'<(.*?)>', address) 
    return adr.group(1) if adr else address 

def check_spf(eml_file_path: str) -> SPFStatus:
    """
    Checks the SPF status of an email.

    :param eml_file_path: Path to the .eml file containing the email.
    :return: SPFStatus enum indicating the SPF status of the email.
    """

    # Opening the email and parsing
    with open(eml_file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    sender = msg.get('Sender', msg['From'])
    sender_email = extract_email(sender)
    domain = sender_email.split('@')[-1].strip()

    ip_address = None
    # Finding the IP of the sender
    # ex : Received: from 20.84.152.113 by 65.23.81.142; ...
    for header in msg.get_all('Received', []):
        match = re.search(r'\[([\d\.]+)\]', header)
        if match:
            ip_address = match.group(1)
            break
    
    # ip not found
    if not ip_address:
        return SPFStatus.NO_IP 

    try:
        # getting the SPF record
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = None
        for r in answers:
            txt_record = r.to_text()
            if 'v=spf1' in txt_record:
                spf_record = txt_record
                break

        if not spf_record:
            return SPFStatus.NO_SPF_RECORD
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return SPFStatus.INVALID_DOMAIN
    except Exception as e:
        return SPFStatus.DNS_ERROR

    try:
        # checking the SPF record
        result = spf.check2(i=ip_address, s=sender_email, h=msg.get('X-HELO', 'N/A'))
        spf_status = result[0]
        if spf_status == 'pass':
            return SPFStatus.VALID
        elif spf_status == 'fail':
            return SPFStatus.INVALID
        elif spf_status == 'softfail':
            return SPFStatus.SOFT_WARNING
        else:
            return SPFStatus.NEUTRAL
    except Exception as e:
        return SPFStatus.SPF_ERROR