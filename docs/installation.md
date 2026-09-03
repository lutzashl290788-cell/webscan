# Installation

WebScan requires **Python 3.11 or later** and runs on Linux, macOS, and
Windows. Runtime dependencies are deliberately minimal: `aiohttp` and `PyYAML`.

## Contents

- [From PyPI](#from-pypi)
- [Optional extras](#optional-extras)
- [From source](#from-source)
- [With Docker](#with-docker)
- [Isolated install with pipx](#isolated-install-with-pipx)
- [Verifying the install](#verifying-the-install)
- [Upgrading and uninstalling](#upgrading-and-uninstalling)

## From PyPI

The distribution is named `webscan-security`; the command it installs is
`webscan`.

```bash
python -m pip install webscan-security
```

Inside a virtual environment (recommended):

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install webscan-security
```

## Optional extras

The base install runs every built-in plugin. Extras add optional subsystems:

| Extra | Install | Adds |
|---|---|---|
| `ai` | `pip install 'webscan-security[ai]'` | `--ai-triage` and `--ai-summary` (needs `ANTHROPIC_API_KEY`) |
| `serve` | `pip install 'webscan-security[serve]'` | `webscan serve` local dashboard |
| `dev` | `pip install 'webscan-security[dev]'` | `pytest`, `ruff`, `mypy` for contributors |

Combine them as needed:

```bash
python -m pip install 'webscan-security[ai,serve]'
```

Without the `ai` extra the AI flags are **silently skipped** rather than
failing, so a script that passes them still works on a base install.

## From source

```bash
git clone https://github.com/lutzashl290788-cell/webscan
cd webscan
python -m pip install .
```

For development, install in editable mode with the dev extra:

```bash
python -m pip install -e ".[dev]"
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full contributor setup.

## With Docker

Images are published to the GitHub Container Registry and run as an
unprivileged user (uid 10001):

```bash
docker run --rm ghcr.io/lutzashl290788-cell/webscan -t https://example.com
```

To keep reports, mount a writable directory and write into it:

```bash
docker run --rm -v "$(pwd)/reports:/reports" \
  ghcr.io/lutzashl290788-cell/webscan \
  -t https://example.com -o /reports/scan --format json html
```

Available tags: `latest` (default branch), `X.Y.Z` and `X.Y` (releases), and
`sha-<commit>`.

## Isolated install with pipx

To keep WebScan off your project's dependency graph while still having the
`webscan` command on your `PATH`:

```bash
pipx install webscan-security
pipx install 'webscan-security[serve]'   # with extras
```

## Verifying the install

```bash
webscan --version        # prints e.g. "webscan 2.8.2"
webscan --list-plugins   # prints all 41 plugins
```

If the `webscan` command is not found but the package installed successfully,
the scripts directory is not on your `PATH`. Use the module form instead:

```bash
python -m webscan --version
```

## Upgrading and uninstalling

```bash
python -m pip install --upgrade webscan-security
python -m pip uninstall webscan-security
```

Uninstalling does not remove local scan history. Delete
`~/.webscan/history.db` (or the path in `WEBSCAN_HISTORY_DB`) if you want it
gone.
