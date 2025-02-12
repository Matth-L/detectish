FROM python:3.11-slim

WORKDIR /app

COPY ./src /app
COPY ./phishing_email_example/test.eml /phishing_email_example/test.eml

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "dkim_check.py"]
