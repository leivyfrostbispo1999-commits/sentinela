FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc g++ && rm -rf /var/lib/apt/lists/*

COPY main.py .

RUN pip install --no-cache-dir confluent-kafka

CMD ["python", "main.py"]