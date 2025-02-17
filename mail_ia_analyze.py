import os
import email
import preprocessing_mail
from bs4 import BeautifulSoup
from email.policy import default
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline


def analyze_emails(file_path):
    """
    Analyzes emails from a file and classifies them.

    This function reads an email file, extracts the text, splits it into groups of tokens,
    and classifies each group using a classifier.

    Parameters:
    file_path (str): The path to the email file to be analyzed.

    Returns:
    list: A list of dictionaries containing classification results for each group of tokens.
          Each dictionary has keys 'label' and 'score'.
    """

    results = []
    text =  preprocessing_mail.extract_email_text(file_path)
    groups_to_analyze = preprocessing_mail.split_512_token(text)

    for sentence in groups_to_analyze:
        prediction = classifier(sentence)
        results.append(prediction)

    return results


def phishing_statistics(group):
    """
    Calculates statistics for phishing and benign labels from classification results.

    This function processes the classification results to count the occurrences of 'phishing'
    and 'benign' labels and calculates the average score for each label.

    Parameters:
    group (list): A list of lists, where each sublist contains dictionaries with 'label' and 'score' keys.

    Returns:
    dict: A dictionary containing the count and average score for 'phishing' and 'benign' labels.
          The dictionary has keys: 'phishing_count', 'phishing_avg_score', 'benign_count', 'benign_avg_score'.
    """
    count_phishing = 0
    count_benign = 0
    score_sum_phishing = 0
    score_sum_benign = 0

    for g in group:
        for item in g:
            label = item.get('label')
            score = item.get('score')

            if label == 'phishing':
                score_sum_phishing += score
                count_phishing += 1
            elif label == 'benign':
                score_sum_benign += score
                count_benign += 1

    score_avg_phishing = score_sum_phishing / count_phishing if count_phishing > 0 else 0
    score_avg_benign = score_sum_benign / count_benign if count_benign > 0 else 0

    return {
        'phishing_count': count_phishing,
        'phishing_avg_score': score_avg_phishing,
        'benign_count': count_benign,
        'benign_avg_score': score_avg_benign
    }

tokenizer = AutoTokenizer.from_pretrained("ealvaradob/bert-finetuned-phishing")
model = AutoModelForSequenceClassification.from_pretrained("ealvaradob/bert-finetuned-phishing")

classifier = pipeline('text-classification', model=model, tokenizer=tokenizer)

test_email = analyze_emails('./mail_test/test.eml')
phishing_mail = analyze_emails('./mail_test/1.eml')


print(phishing_statistics(test_email))
print(phishing_statistics(phishing_mail))