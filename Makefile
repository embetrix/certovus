.PHONY: dev down test unit e2e docker-build docker-test staging prod lint format clean

# ── local dev stack (pebble + challtestsrv + broker in Docker) ───────────────

dev:
	docker compose up --build -d
	@echo "Stack is up. Logs: docker compose logs -f  |  Stop: make down"

down:
	docker compose down -v

# ── test targets (run locally against host Python) ────────────────────────────

test: unit e2e

unit:
	pytest tests/unit/ -v; s=$$?; [ $$s -eq 5 ] && exit 0 || exit $$s

e2e:
	pytest tests/e2e/ -v; s=$$?; [ $$s -eq 5 ] && exit 0 || exit $$s

# ── Docker test targets ───────────────────────────────────────────────────────

docker-build:
	docker compose build broker

# Runs the unit test suite inside the broker container.
docker-test:
	docker compose run --rm --entrypoint pytest broker tests/unit/ -v

# Runs the e2e test suite inside Docker (needs pebble + challtestsrv).
e2e:
	docker compose run --rm --entrypoint pytest broker tests/e2e/ -v; s=$$?; [ $$s -eq 5 ] && exit 0 || exit $$s

# ── staging / prod (run on VPS under systemd, not locally) ────────────────────

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
