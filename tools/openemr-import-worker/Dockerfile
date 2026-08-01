ARG PYTHON_VERSION=3.14
FROM python:${PYTHON_VERSION}-alpine

RUN apk add --no-cache ca-certificates curl mariadb-client \
    && curl --fail --silent --show-error --location \
      --output /etc/ssl/certs/aws-rds-global.pem \
      https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
    && test -s /etc/ssl/certs/aws-rds-global.pem \
    && adduser -D -u 1000 importer \
    && mkdir -p /work \
    && chown importer:importer /work

WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --requirement requirements.txt

COPY worker.py .

USER importer
ENTRYPOINT ["python", "/app/worker.py"]
