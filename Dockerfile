FROM python:3.12-slim

# cryptography wheel needs gcc + libssl-dev
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install deps in a layer that only rebuilds when pyproject.toml changes.
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[dev]"

COPY . .

ENV CERTOVUS_ENV=dev

# Default: run unit tests.
# Override via docker-compose `command:` or `docker-compose run broker <cmd>`.
CMD ["pytest", "tests/unit/", "-v"]
