FROM python:3.11-slim

WORKDIR /detectish

RUN apt-get update && apt-get install -y make

COPY ./src .
COPY ./phishing_email_example ./phishing_email_example
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["sh"]
CMD ["python","ai_analysis/ai_analysis.py"]

