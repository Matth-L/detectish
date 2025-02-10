FROM python:3.11-slim

WORKDIR /app

COPY ./src /app
COPY ./phishing_email_example/0.eml /phishing_email_example/0.eml
COPY ./phishing_email_example/1.eml /phishing_email_example/1.eml
COPY ./phishing_email_example/2.eml /phishing_email_example/2.eml
COPY ./phishing_email_example/test.eml /phishing_email_example/test.eml

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "spf_check.py"]
