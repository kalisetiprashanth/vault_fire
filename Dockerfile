FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 TV_DATA_DIR=/data TV_TRUST_PROXY=1 TV_SECURE_COOKIES=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m tv && mkdir -p /data && chown -R tv /data
USER tv
EXPOSE 8000
# one worker + threads: SQLite is the store; BEGIN IMMEDIATE serialises writers.
CMD ["sh","-c","gunicorn wsgi:application --bind 0.0.0.0:${PORT:-8000} --workers 1 --threads 4 --timeout 60"]
