# syntax=docker/dockerfile:1.7

# ─── Build stage ──────────────────────────────────────────────────────────────
# Digest-pinned for reproducibility (CWE-1357). To update, pull the new digest
# from `docker pull python:3.12-slim && docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim`.
FROM python:3.12-slim@sha256:c2d8472b831337ab296a8ce652e1ba786e9e3034fc445dc58b50a7f5251f0003 AS build

WORKDIR /src

# Install build tooling, then the package into an isolated prefix.
COPY pyproject.toml README.md LICENSE ./
COPY webscan ./webscan

RUN python -m pip install --no-cache-dir --upgrade pip build \
    && python -m pip install --no-cache-dir --prefix=/install .

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:c2d8472b831337ab296a8ce652e1ba786e9e3034fc445dc58b50a7f5251f0003 AS runtime

# Copy the installed package and its dependencies from the build stage.
COPY --from=build /install /usr/local

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /home/scanner

# Healthcheck: verify the CLI binary is functional. Lightweight (no network)
# so it works in any deployment, including those without a `serve` backend.
# `--format json` exits 0 with a single empty-targets error message before
# doing any work, so this doubles as a smoke test of the import surface.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD webscan --help >/dev/null 2>&1 || exit 1

ENTRYPOINT ["webscan"]
CMD ["--help"]
