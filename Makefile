.PHONY: install format lint test benchmark demo docker clean

install:
	uv sync --frozen --all-extras

format:
	uv run ruff format .
	uv run ruff check --fix .

lint:
	uv lock --check
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy src

test:
	uv run pytest --cov=security_telemetry_platform --cov-report=term-missing --cov-report=xml

benchmark:
	uv run sectel benchmark --iterations 200

demo:
	uv run sectel serve --host 127.0.0.1 --port 8080

docker:
	docker compose up --build

clean:
	rm -rf .coverage coverage.xml reports/*.json reports/*.md
