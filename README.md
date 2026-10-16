# Orbit Auth RBAC

`orbit-auth-rbac` maps trusted role identifiers to exact application permissions. It builds on the
`orbit-auth` capability and Core's structured security-error contract. Its `Principal` already
satisfies the structural `RoleSubject` protocol; applications can also pass their own trusted
subject type:

```bash
pip install orbit-auth-rbac
```

```python
from orbit_auth import Identity, Principal
from orbit_auth_rbac import PermissionAuthorizer, PermissionDenied


authorizer = PermissionAuthorizer(
    {
        "catalog-reader": {"catalog.read"},
        "catalog-editor": {"catalog.read", "catalog.write"},
    }
)
subject = Principal(
    identity=Identity(subject="operator-17", provider="internal"),
    roles=frozenset({"catalog-editor"}),
)

try:
    authorizer.require(subject, "catalog.write")
except PermissionDenied:
    ...  # map this typed failure to the host framework's forbidden response
```

The grant map and optional role graph are detached and immutable. A policy allows at most 1,024
roles, 4,096 permissions per role, and 65,536 combined grants/inheritance edges. Inheritance must
form an acyclic directed graph; child roles receive their parents' permissions transitively.
Optional per-permission attribute bindings require trusted subject claims to equal resource fields,
for example matching `region_id` and `tenant_id` before allowing a record operation. Missing or
type-mismatched values deny access. Role and permission identifiers are at most 255 characters and
use the documented ASCII identifier syntax. Anonymous subjects and unknown roles are denied. The
subject must expose roles as an immutable `frozenset[str]` with validated role identifiers.

`PermissionDenied` is a Core `OrbitError` in the security category with stable code `rbac.forbidden`
and a generic message. It does not include the requested permission or grant contents. Application
code is responsible for supplying roles and claims from a verified security boundary and mapping
this exception into its transport response. Passing role or attribute values supplied directly by
an untrusted request is unsafe.

## Documentation

The package-specific guides cover [architecture](docs/architecture/overview.md), [operations and security](docs/operations/README.md), and [development](docs/development/README.md), with [security guidance](docs/security/overview.md). The [documentation index](docs/README.md) links to the full package overview and project policies.

## Development

```bash
python -m pip install -e '.[dev]'
pytest
ruff check .
mypy
```

## Status

This is a **v0.1.0-alpha review candidate**, not a published release. On CPython 3.11.14, 3.12.14,
3.13.15, and 3.14.7, all 20 tests, Ruff lint and format checks, strict mypy, dependency audits, and
wheel/sdist builds pass locally. Hosted CI and application-level authorization-policy review remain
release gates. The policy API may change before stable release.

Licensed under Apache-2.0.

