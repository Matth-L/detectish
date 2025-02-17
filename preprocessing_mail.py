import email
import html2text
import re
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import nltk

nltk.download('punkt_tab')

def clean_email_text(text:str)->str:
    """
    @brief Cleans an email text.
    
    This function cleans the input email text by performing the following operations:
      - Replaces newline characters (both '\\n' and actual newlines) with a space.
      - Removes HTML tags.
      - Removes any sequences of two or more dashes.
      - Replaces multiple consecutive whitespace characters with a single space and trims extra spaces.
      - Removes isolated pipe characters ('|') that appear between spaces or at the beginning/end of the text.
    
    @param text The raw email text to be cleaned.
    @return The cleaned email text.
    """
    text = re.sub(r'(\\n|\n)', ' ', text) # newline
    text = re.sub(r'<[^>]+>', '', text) # html tags
    # Remove any sequences of dashes
    text = re.sub(r'-{2,}', '', text) #remove --, --- etc.
    text = re.sub(r'\s+', ' ', text).strip() #  extra space
    text = re.sub(r'(?<=\s)\|(?=\s)|^\||\|$', '', text) # isolated pipes
    return text

def extract_email_text(file_path)->str:
    """
    @brief Extracts and cleans email text from a file.

    This function opens the email file located at the specified file_path, parses it into an email message object,
    and extracts the text content. For multipart emails, it walks through the parts to retrieve either the "text/plain"
    or "text/html" content. If HTML content is found, it converts it to plain text using html2text. Finally, the extracted
    text is cleaned using the clean_email_text function.

    @param file_path The path to the email file.
    @return The cleaned text extracted from the email.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        msg = email.message_from_file(f)

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                text = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
            elif content_type == "text/html":
                html = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
                text = html2text.html2text(html)
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            text = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')
        elif content_type == "text/html":
            html = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')
            text = html2text.html2text(html)

    return clean_email_text(text)

def split_512_token(text: str):
    """
    Splits a given text into groups of sentences, ensuring each group does not exceed 512 tokens.

    This function tokenizes the input text into sentences and groups them such that the total number
    of tokens in each group does not exceed 512. It uses a pre-trained tokenizer from the Hugging Face
    transformers library.

    Parameters:
    text (str): The input text to be split into groups of sentences.

    Returns:
    list: A list of lists, where each sublist contains sentences whose total token count does not exceed 512.
    """

    # Initialiser le tokenizer
    tokenizer = AutoTokenizer.from_pretrained("ealvaradob/bert-finetuned-phishing")

    # Segmenter le texte en phrases
    sentences = nltk.sent_tokenize(text)

    # Initialiser des variables pour suivre les groupes de tokens
    current_group = []
    current_group_tokens = 0
    all_groups = []

    # Parcourir chaque phrase
    for sentence in sentences:

        # Tokeniser la phrase
        tokens = tokenizer.tokenize(sentence)
        num_tokens = len(tokens)

        # Vérifier si l'ajout de cette phrase dépasse la limite de 512 tokens
        if current_group_tokens + num_tokens > 512:
            # Si oui, finaliser le groupe actuel et commencer un nouveau groupe
            all_groups.append(current_group)
            current_group = []
            current_group_tokens = 0

        # Ajouter la phrase au groupe actuel
        current_group.append(sentence)
        current_group_tokens += num_tokens

    # Ajouter le dernier groupe s'il n'est pas vide
    if current_group:
        all_groups.append(current_group)

    return all_groups

