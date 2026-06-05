FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir ".[all]"

ENV POLICYPULSE_LOG=INFO

ENTRYPOINT ["policy-pulse-mcp"]
