FROM python:3.13.5

WORKDIR /app

RUN pip install poetry

COPY README.md LICENSE pyproject.toml poetry.lock ./
COPY nickel/ ./nickel/
RUN poetry config virtualenvs.create false && poetry install --without=dev

EXPOSE 8000

CMD ["sh", "-c", "uvicorn nickel.server:app --host 0.0.0.0 --port ${PORT:-8000}"]
