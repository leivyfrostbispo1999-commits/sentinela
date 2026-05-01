<<<<<<< HEAD
FROM python:3.11-slim

# Instala dependências nativas para o conector do Postgres
RUN apt-get update && apt-get install -y gcc libpq-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copia e instala as dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código do sink
COPY alert_sink.py ./main.py

ENV PYTHONUNBUFFERED=1
CMD ["python", "main.py"]
=======
FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
>>>>>>> f33ed383d8e88d290a27dd7885af588db7e1ce40
