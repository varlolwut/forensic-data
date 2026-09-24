FROM ghcr.io/astral-sh/uv:0.12.18@sha256:34532673531cdce6019c0919595b2b7f9207ed3a46dabc606d563c4c569cf82a AS uv

FROM scratch AS libpq

ADD --checksum=sha256:1862241d49dd0afe33ba3bfad14434975e5fbd15902b09215a04dc2796d76cd5 \
    https://apt-archive.postgresql.org/pub/repos/apt/pool/17/p/postgresql-17/libpq5_17.11-1.pgdg12+2_amd64.deb \
    /libpq5.deb
ADD --checksum=sha256:1537cce8c942cfbba02dee1627542a2f05ff1de54404dd4d50f00f39cf0ff778 \
    https://apt-archive.postgresql.org/pub/repos/apt/pool/17/p/postgresql-17/libpq-dev_17.11-1.pgdg12+2_amd64.deb \
    /libpq-dev.deb

FROM scratch AS msodbcsql

ADD --checksum=sha256:f506cb3de8b34cd94e9014d247b39e9dfd7effad79edad3ab67096dc3c1b6b0e \
    https://packages.microsoft.com/debian/12/prod/pool/main/m/msodbcsql18/msodbcsql18_18.7.1.1-1_amd64.deb \
    /msodbcsql18.deb

FROM python:3.12.14-slim-bookworm@sha256:1aaa65a85fda306ffb8b910824d4e93bdce61e212c7e87168123ea3073b41a1a AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

COPY --from=uv /uv /uvx /usr/local/bin/
COPY --from=libpq /libpq5.deb /libpq-dev.deb /tmp/

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        libssl-dev \
        /tmp/libpq5.deb \
        /tmp/libpq-dev.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/libpq5.deb /tmp/libpq-dev.deb

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

COPY --from=libpq /libpq5.deb /tmp/libpq5.deb
COPY --from=msodbcsql /msodbcsql18.deb /tmp/msodbcsql18.deb

RUN apt-get update \
    && ACCEPT_EULA=Y DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        ca-certificates \
        libgssapi-krb5-2 \
        /tmp/libpq5.deb \
        /tmp/msodbcsql18.deb \
    && test "$(dpkg-query --show --showformat='${Version}' msodbcsql18)" = "18.7.1.1-1" \
    && rm -rf /var/lib/apt/lists/* /tmp/libpq5.deb /tmp/msodbcsql18.deb \
    && groupadd --gid 10001 dfe \
    && useradd --uid 10001 --gid dfe --create-home --home-dir /home/dfe dfe

WORKDIR /app
COPY --from=build /app/.venv /app/.venv

USER 10001:10001

ENTRYPOINT ["forensics"]
CMD ["--help"]
