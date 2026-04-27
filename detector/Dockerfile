FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1
ENV HNG_CONFIG=/app/config.yaml

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-u", "main.py"]
