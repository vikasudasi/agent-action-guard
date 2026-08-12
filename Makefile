.PHONY: install lint typecheck test verify

install:
	pip install -e ".[dev]"

lint:
	ruff check .
	ruff format --check .

typecheck:
	mypy guard cli

test:
	pytest -q

verify: lint typecheck test
