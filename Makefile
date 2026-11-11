.PHONY: install test lint audit run
install:
	python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
test:
	pytest -q
lint:
	ruff check src tests
audit:
	pip-audit
run:
	uvicorn exposureguard.api.main:create_app --factory --reload
