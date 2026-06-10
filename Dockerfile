# syntax=docker/dockerfile:1

# ─── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS build

WORKDIR /src

# Install build tooling, then the package into an isolated prefix.
COPY pyproject.toml README.md LICENSE ./
COPY webscan ./webscan

RUN python -m pip install --no-cache-dir --upgrade pip build \
    && python -m pip install --no-cache-dir --prefix=/install .

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Copy the installed package and its dependencies from the build stage.
COPY --from=build /install /usr/local

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /home/scanner

ENTRYPOINT ["webscan"]
CMD ["--help"]
