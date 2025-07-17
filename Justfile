lint:
    ruff format
    isort . --profile black

dev:
    poetry run uvicorn nickel.server:app --reload
