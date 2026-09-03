## Summary

<!-- One or two sentences: what does this PR do and why? -->

## Type of change

- [ ] Bug fix
- [ ] New plugin
- [ ] Enhancement to an existing plugin or feature
- [ ] Refactor / cleanup (no behaviour change)
- [ ] Documentation
- [ ] CI / build / packaging

## Checklist

- [ ] `pytest` passes locally
- [ ] `ruff check .` passes (no lint errors)
- [ ] `mypy webscan` passes (no type errors)
- [ ] New/changed behaviour is covered by tests
- [ ] New plugin is registered under `[project.entry-points."webscan.plugins"]` in `pyproject.toml`
- [ ] Docs updated (`README.md` and/or `docs/`) if user-facing behaviour changed
- [ ] `CHANGELOG.md` updated for user-facing changes
- [ ] PR title follows `<type>: <short description>` convention

## Scanning behaviour

<!-- Skip if this PR does not touch scanning. -->

- [ ] No new requests are sent on a default run, **or** the new plugin is registered as opt-in
- [ ] Findings are content-verified and carry an appropriate `confidence` level
- [ ] Each new finding carries a `remediation` string
- [ ] `run()` never raises — network and timeout errors return partial results

## Testing notes

<!-- Describe how you tested this change.
     For plugins: include the FakeSession scenario that demonstrates both the
     finding and the "no finding when safe" path. -->

## Related issues

<!-- Closes #<number> -->
