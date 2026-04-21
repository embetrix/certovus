.PHONY: dev down test unit e2e staging prod lint format clean

# ── local dev stack (pebble + challtestsrv + nginx + broker in Docker) ────────

dev:
	docker-compose up --build -d
	@echo "Stack is up. Logs: docker-compose logs -f  |  Stop: make down"

down:
	docker-compose down -v

# ── test targets ──────────────────────────────────────────────────────────────

test: unit e2e

unit:
	pytest tests/unit/ -v

e2e:
	pytest tests/e2e/ -v

# ── staging / prod (run on VPS under systemd, not locally) ────────────────────

staging:
	CERTOVUS_ENV=staging \
	  gunicorn \
	    --bind 127.0.0.1:8080 \
	    --workers 4 \
	    --access-logfile - \
	    --error-logfile - \
	    "broker.app:create_app()"

prod:
	CERTOVUS_ENV=production \
	  gunicorn \
	    --bind 127.0.0.1:8080 \
	    --workers 4 \
	    --access-logfile - \
	    --error-logfile - \
	    "broker.app:create_app()"

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
