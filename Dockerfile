FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data

EXPOSE 8080

# 使用 Railway 注入的 $PORT，若無則預設 8080
CMD gunicorn --bind "0.0.0.0:${PORT:-8080}" --workers 2 --timeout 120 app:app
