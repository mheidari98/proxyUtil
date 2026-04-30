.PHONY: dev test lint format coverage build clean

dev:
	uv sync --all-extras

test:
	uv run pytest -v

lint:
	uv run ruff check .
	uv run ruff format --check .

format:
	uv run ruff check . --fix
	uv run ruff format .

coverage:
	uv run pytest --cov=proxyUtil --cov-report=term-missing --cov-report=xml

build:
	uv build

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache htmlcov coverage.xml report.xml
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
