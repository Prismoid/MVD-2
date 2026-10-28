FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    sqlalchemy \
    psycopg2-binary \
    cryptography \
    requests \
    ecdsa \
    httpx \
    pyOpenSSL

COPY app /app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7650"]