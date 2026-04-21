FROM python:3.12-slim

# cryptography wheel needs gcc + libssl-dev
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── deps layer ────────────────────────────────────────────────────────────────
# Install dependencies before copying source so this layer is only invalidated
# when pyproject.toml changes, not on every code edit.
# tomllib (stdlib 3.11+) reads deps directly from pyproject.toml.
COPY pyproject.toml .
RUN pip install --no-cache-dir $(python3 -c "import tomllib,sys; d=tomllib.load(open('pyproject.toml','rb')); deps=d['project']['dependencies']+sum(d['project'].get('optional-dependencies',{}).values(),[]); print(' '.join(deps))")

# ── source layer ──────────────────────────────────────────────────────────────
# Copy source then install the package itself (no dep resolution — fast).
COPY . .
RUN pip install --no-cache-dir --no-deps -e .

ENV CERTOVUS_ENV=dev

# Default: run unit tests.
# Override via docker-compose `command:` or `docker compose run broker <cmd>`.
CMD ["pytest", "tests/unit/", "-v"]
