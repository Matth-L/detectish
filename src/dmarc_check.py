import dns.resolver
from email import policy
from email.parser import BytesParser
from enum import Enum
from spf_check import check_spf, SPFStatus
from dkim_check import check_dkim, DKIMStatus

class DMARCStatus(Enum):
    PASS = "DMARC pass: email is aligned with DMARC policy."
    FAIL = "DMARC fail: email does not align with DMARC policy."
    NO_DMARC = "No DMARC record found for this domain."
    DNS_ERROR = "DNS error."
    DMARC_ERROR = "Error during DMARC verification."

def extract_email(address: str) -> str:
    """Extracts the email address from a From or Sender field."""
    import re
    match = re.search(r'<(.*?)>', address)
    return match.group(1) if match else address

def check_dmarc(eml_file_path: str) -> DMARCStatus:
    """
    Checks the DMARC status of an email. 
    If it exists and spf + dkim OK, Pass
    """
    # getting spf + dkim status
    spf_status = check_spf(eml_file_path)
    dkim_status = check_dkim(eml_file_path)

    with open(eml_file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    sender = msg.get('Sender', msg['From'])
    sender_email = extract_email(sender)
    domain = sender_email.split('@')[-1].strip()

    try:
        dmarc_record = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
        dmarc_policy = None
        for record in dmarc_record:
            for txt_string in record.strings:
                # check if there is dmarc1 label 
                if txt_string.decode().startswith('v=DMARC1'):
                    dmarc_policy = txt_string.decode()
                    break

        if not dmarc_policy:
            return DMARCStatus.NO_DMARC

        # there is a dmark policy, check if spf and dkim ok
        if (spf_status == SPFStatus.VALID or dkim_status == DKIMStatus.VALID):
            return DMARCStatus.PASS
        else:
            return DMARCStatus.FAIL

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return DMARCStatus.NO_DMARC
    except Exception as e:
        return DMARCStatus.DMARC_ERROR