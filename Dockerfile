FROM python:3.11-slim

RUN apt-get update && apt-get install -y git

WORKDIR /app

COPY requirements.txt .

ARG REPO_URL=https://github.com/Matth-L/detectish.git
RUN git clone $REPO_URL .

RUN pip install --no-cache-dir -r requirements.txt

#CMD ["python", "app.py"]
