FROM python:3.11-slim

WORKDIR /app

COPY ./src /app
COPY ./phishing_email_example/1.eml /phishing_email_example/1.eml
COPY ./phishing_email_example/2.eml /phishing_email_example/2.eml

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "mail_analyzer.py"]
