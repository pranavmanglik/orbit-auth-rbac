# Orbit Auth RBAC: development

The package declares Python `>=3.11,<3.15` support. Confirm actual per-version hosted CI results
before claiming that the full range has been exercised.

## Local checks

In a workspace checkout, install the sibling capability followed by this package's development
tools:

```bash
python -m pip install -e ../orbit-auth
python -m pip install -e '.[dev]'
pip-audit --skip-editable --progress-spinner off
pytest
ruff check src tests
ruff format --check src tests
mypy
```

The tests need no database, network service, or external identity provider. They cover exact grant
union, default denial, immutable policy snapshots, role subject validation, identifier/cardinality
bounds, sanitized errors, and membership checks that avoid unnecessary permission materialization.

## Contract changes

Preserve the separation between authenticated identity and permission evaluation. When changing role
or permission identifier rules, check compatibility with `orbit-auth` roles and add tests for
boundary lengths, invalid characters, mutation of source mappings after construction, and unknown
roles. Document any change to grant semantics, exception codes, role cardinality, or policy lifecycle
in the README and architecture/security guides.

Report exact Python/tool versions and test results. Local tests verify this evaluator's behavior;
they do not verify upstream role provenance or application authorization policy.

The current local quality matrix passes on CPython 3.11, 3.12, 3.13, and 3.14: all 20 tests, Ruff
lint and format checks, strict mypy, dependency audits, and wheel/sdist builds pass on each
interpreter. Editable Core and Auth distributions are skipped by pip-audit and are audited in their
own repositories. This covers deterministic policy evaluation only; application route protection
and authorization-policy review remain responsibilities of the integrating application.
