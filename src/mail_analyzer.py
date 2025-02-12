from dmarc_check import check_dmarc, DMARCStatus
from spf_check import check_spf, SPFStatus
from dkim_check import check_dkim, DKIMStatus

def analyze_email(eml_file_path: str):
    """Analyzes an email for SPF, DKIM, and DMARC status and prints the results."""
    spf_status = check_spf(eml_file_path)
    dkim_status = check_dkim(eml_file_path)
    dmarc_status = check_dmarc(eml_file_path)

    print(f"SPF Status: {spf_status.value}")
    print(f"DKIM Status: {dkim_status.value}")
    print(f"DMARC Status: {dmarc_status.value}")

if __name__ == "__main__":

    analyze_email("/phishing_email_example/1.eml")
    analyze_email("/phishing_email_example/2.eml")
