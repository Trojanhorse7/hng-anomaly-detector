FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV HNG_CONFIG=/app/config.yaml

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-u", "main.py"]
