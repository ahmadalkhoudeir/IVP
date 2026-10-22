FROM python:3.11-slim

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000

# PORT is set by hosts such as Render; 8000 locally. --proxy-headers makes the
# app see https behind a TLS-terminating proxy, so the session cookie gets
# the Secure flag.
CMD ["sh", "-c", "uvicorn ivp.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips='*'"]
