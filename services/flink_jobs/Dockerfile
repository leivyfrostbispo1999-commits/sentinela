FROM flink:1.18.1-scala_2.12

# Instalar Python e PyFlink
RUN apt-get update && apt-get install -y python3 python3-pip python3-dev && rm -rf /var/lib/apt/lists/*
RUN ln -s /usr/bin/python3 /usr/bin/python

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

WORKDIR /app
COPY correlation_job.py .

# Comando para rodar como standalone job
CMD ["python", "correlation_job.py"]
