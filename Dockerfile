FROM ghcr.io/astral-sh/uv:0.12.18@sha256:34532673531cdce6019c0919595b2b7f9207ed3a46dabc606d563c4c569cf82a AS uv

FROM python:3.12.14-slim-bookworm@sha256:1aaa65a85fda306ffb8b910824d4e93bdce61e212c7e87168123ea3073b41a1a AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY --from=uv /uv /uvx /usr/local/bin/

COPY README.md pyproject.toml uv.lock ./
RUN uv sync --frozen --only-group build --no-install-project

COPY src ./src
RUN uv lock --check \
    && uv build --no-build-isolation --no-create-gitignore --wheel --out-dir /dist \
    && uv sync --frozen --no-dev --no-editable

FROM python:3.12.14-slim-bookworm@sha256:1aaa65a85fda306ffb8b910824d4e93bdce61e212c7e87168123ea3073b41a1a AS runtime

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 dfe \
    && useradd --uid 10001 --gid dfe --create-home --home-dir /home/dfe dfe

WORKDIR /app
COPY --from=build /app/.venv /app/.venv

USER 10001:10001

ENTRYPOINT ["forensics"]
CMD ["--help"]
