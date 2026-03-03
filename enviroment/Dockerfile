FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    flask \
    flask-limiter \
    gunicorn

COPY app/ ./app/

EXPOSE 8000

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app.main:app"]
