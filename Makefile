.PHONY: dev down test unit e2e docker-build docker-test staging prod lint format clean

# ── local dev stack ───────────────────────────────────────────────────────────

dev:
	docker compose up --build -d
	@echo "Stack is up. Logs: docker compose logs -f  |  Stop: make down"

down:
	docker compose down -v

# ── test targets (all run inside Docker so pebble is reachable) ───────────────

# Run unit + e2e suites.
test: docker-test e2e

# Unit tests only (fast, no pebble needed).
docker-test:
	docker compose run --rm --entrypoint pytest broker tests/unit/ -v

# End-to-end tests (requires pebble; starts it automatically via depends_on).
e2e:
	docker compose run --rm --entrypoint pytest broker tests/e2e/ -v; \
	  s=$$?; [ $$s -eq 5 ] && exit 0 || exit $$s

# ── Docker image ──────────────────────────────────────────────────────────────

docker-build:
	docker compose build broker

# ── staging / prod (run on VPS under systemd) ─────────────────────────────────

staging:
	CERTOVUS_ENV=staging \
	  gunicorn \
	    --bind 127.0.0.1:8080 \
	    --workers 4 \
	    --access-logfile - \
	    --error-logfile - \
	    broker.wsgi:app

prod:
	CERTOVUS_ENV=production \
	  gunicorn \
	    --bind 127.0.0.1:8080 \
	    --workers 4 \
	    --access-logfile - \
	    --error-logfile - \
	    broker.wsgi:app

# ── code quality ──────────────────────────────────────────────────────────────

lint:
	ruff check broker/ tools/ tests/
	mypy broker/ tools/

format:
	ruff format broker/ tools/ tests/
	ruff check --fix broker/ tools/ tests/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache dist build *.egg-info
