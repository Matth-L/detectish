import email
import re
import dns.resolver
from email import policy
from email.parser import BytesParser
from enum import Enum
import dkim

class DKIMStatus(Enum):
    """
    Enum class for the DKIM status of an email.
    """
    VALID = "DKIM valid: signature is valid."
    INVALID = "DKIM invalid: signature is invalid."
    NO_DKIM = "No DKIM signature found."
    DNS_ERROR = "DNS error."
    DKIM_ERROR = "Error during DKIM verification."

def extract_dkim_domain_selector(dkim_header: str):
    """
    Extracts the domain and selector from the DKIM-Signature header.

    :param dkim_header: The DKIM-Signature header value.
    :return: A tuple containing the domain and selector.
    """
    # From wikipedia, the dkim message will look like this, 
    # we need d= and s=
    # DKIM-Signature: v=1; a=rsa-sha256; d=example.net; s=brisbane;
    #  c=relaxed/simple; q=dns/txt; i=foo@eng.example.net;
    #  t=1117574938; x=1118006938; l=200;
    #  h=from:to:subject:date:keywords:keywords;
    #  z=From:foo@eng.example.net|To:joe@example.com|
    #    Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
    #  bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
    #  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZ
    #           VoG4ZHRNiYzR

    d = re.search(r'\bd=([^;]+)', dkim_header)
    s = re.search(r'\bs=([^;]+)', dkim_header)

    if not d or not s:
        return None, None
    
    #(d,s)
    return d.group(1), s.group(1)

def check_dkim(eml_file_path: str) -> DKIMStatus:
    """
    Checks the DKIM status of an email.

    :param eml_file_path: Path to the .eml file containing the email.
    :return: DKIMStatus enum indicating the DKIM status of the email.
    """
    with open(eml_file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    dkim_header = msg.get('DKIM-Signature')
    if not dkim_header:
        return DKIMStatus.NO_DKIM

    domain, selector = extract_dkim_domain_selector(dkim_header)
    if not domain or not selector:
        return DKIMStatus.NO_DKIM

    try:
        # now that we have (d,s)
        # we look for the public key in the dns.txt
        dns_txt_record = dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
        public_key = None
        for record in dns_txt_record:
            for txt_string in record.strings:
                if txt_string.decode().startswith('v=DKIM1'):
                    public_key = txt_string.decode()
                    break

        if not public_key:
            return DKIMStatus.NO_DKIM

        # a public key exist, so the dkim was signed
        # dkim.Verifier exists, and allow us to check if the dkim is valid
        try:
            verifier = dkim.DKIM(msg.as_bytes())
            if verifier.verify():
                return DKIMStatus.VALID
            else:
                return DKIMStatus.INVALID
        except dkim.ValidationError:
            return DKIMStatus.INVALID
        except Exception as e:
            return DKIMStatus.DKIM_ERROR

    except dns.resolver.NoAnswer:
        return DKIMStatus.DNS_ERROR
    except dns.resolver.NXDOMAIN:
        return DKIMStatus.DNS_ERROR
    except Exception as e:
        return DKIMStatus.DKIM_ERROR