FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-dev build-essential libffi-dev \
    xmlsec1 curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create venv and install SATOSA from PyPI
RUN uv venv /opt/venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN uv pip install SATOSA gunicorn requests "cryptography<44" "pyOpenSSL>=23,<25"

# Copy our federation plugin
COPY plugin/ /opt/satosa/plugin/

# Copy configuration
COPY etc/ /opt/satosa/etc/

WORKDIR /opt/satosa

EXPOSE 8080

# Plain HTTP - Caddy handles TLS in front
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "satosa.wsgi:app"]
