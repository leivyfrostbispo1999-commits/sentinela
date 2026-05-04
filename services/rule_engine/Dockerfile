FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
COPY threat_intel.py .
COPY rules.yaml .
COPY sentinela_rules.yml .
CMD ["python", "main.py"]
