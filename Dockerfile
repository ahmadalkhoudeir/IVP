FROM python:3.11-slim

RUN pip install --no-cache-dir uv

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src ./src

RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:${PATH}"

EXPOSE 8000

CMD ["uvicorn", "ivp.main:app", "--host", "0.0.0.0", "--port", "8000"]
