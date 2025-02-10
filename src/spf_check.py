import email
import re
import spf
import dns.resolver
from email import policy
from email.parser import BytesParser

def extract_email(address):
    """Extrait l'adresse email d'un champ From ou Sender."""
    match = re.search(r'<(.*?)>', address)
    return match.group(1) if match else address

def check_spf(eml_file_path):
    with open(eml_file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    from_address = msg['From']
    sender = msg.get('Sender', from_address)
    helo = msg.get('X-HELO', 'N/A')
    sender_email = extract_email(sender)

    received_headers = msg.get_all('Received', [])
    ip_address = None

    for header in received_headers:
        match = re.search(r'\[([\d\.]+)\]', header)
        if match:
            ip_address = match.group(1)
            break

    if not ip_address:
        print("Adresse IP non trouvée.")
        return

    domain = sender_email.split('@')[-1].strip()
    print(f"Vérification de l'enregistrement SPF pour le domaine : {domain}")

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = [r.to_text() for r in answers if 'v=spf1' in r.to_text()]
        if spf_record:
            print(f"Enregistrement SPF trouvé : {spf_record[0]}")
        else:
            print("Aucun enregistrement SPF trouvé pour ce domaine.")
    except dns.resolver.NoAnswer:
        print("Pas de réponse DNS pour le domaine.")
        return
    except dns.resolver.NXDOMAIN:
        print("Le domaine n'existe pas.")
        return
    except Exception as e:
        print(f"Erreur lors de la recherche de l'enregistrement SPF : {e}")
        return

    try:
        result = spf.check2(i=ip_address, s=sender_email, h=helo)
        spf_status = result[0]
        if spf_status == 'pass':
            print("SPF valide : l'expéditeur est autorisé.")
        elif spf_status in ['fail', 'softfail']:
            print("SPF invalide : l'expéditeur n'est pas autorisé.")
        elif spf_status == 'neutral':
            print("SPF neutre : aucune politique stricte définie.")
        else:
            print("SPF inconnu ou non applicable.")
    except Exception as e:
        print(f"Erreur lors de la vérification SPF : {e}")

print("Mail 0")
check_spf('/phishing_email_example/0.eml')
print("\nMail 1")
check_spf('/phishing_email_example/1.eml')
print("\nMail 2")
check_spf('/phishing_email_example/2.eml')
print("\nMail 3")
check_spf('/phishing_email_example/test.eml')