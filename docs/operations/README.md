# Orbit Auth RBAC: operations

`PermissionAuthorizer` is a synchronous, in-memory policy object. It opens no connections and reads
no environment variables or files. Construct it from trusted application configuration during
composition, then inject it into the service or policy boundary that performs permission checks.

```python
from orbit_auth import Principal
from orbit_auth_rbac import PermissionAuthorizer

permissions = PermissionAuthorizer(
    {
        "catalog-reader": {"catalog.read"},
        "catalog-editor": {"catalog.read", "catalog.write"},
    }
)


def can_edit_catalog(subject: Principal | None) -> bool:
    return permissions.allows(subject, "catalog.write")
```

For tenant or record scope, bind trusted identity claims to fields from the server-loaded resource:

```python
permissions = PermissionAuthorizer(
    {"regional-editor": {"records.update"}},
    attribute_bindings={"records.update": {"tenant_id": "tenant_id", "region_id": "region_id"}},
)
allowed = permissions.allows(
    verified_principal,
    "records.update",
    resource_attributes={"tenant_id": record.tenant_id, "region_id": record.region_id},
)
```

Do not accept resource attributes used for authorization from the request body. Load them from the
database or another trusted server-side source.

Use `require()` when the calling layer needs a typed `PermissionDenied` failure; use `allows()` for
a boolean policy branch. Map denial to the transport's 403 behavior in the application. This
package does not install HTTP routes or integrate itself with Core's route-role authorizer.

## Policy updates and runtime bounds

The grant mapping is copied and made immutable at construction. There is no runtime grant mutation,
reload endpoint, persistence, or event propagation. To change configured grants, compose and publish
a replacement authorizer and update every relevant application worker. Role membership comes from
each request's verified `RoleSubject`, not from policy state stored here.

The evaluator bounds policy role and grant counts and validates subject role cardinality and
identifier syntax on each call. Keep normal application policies much smaller than the defensive
maximums. The evaluator performs set membership over the subject's roles and only materializes the
full permission union when `permissions_for()` is requested.

## Troubleshooting

- `PermissionDenied` means the subject is anonymous or none of its known roles grants the exact
  requested permission.
- Unknown role values are ignored for grants. Check the trusted role mapping; do not add wildcard
  matching to work around a naming mismatch.
- `TypeError` or `ValueError` indicates malformed policy, subject attributes, or
  role/permission identifiers.
  Treat these as configuration or integration defects rather than authorization denials.
- Permission identifiers are case-sensitive and are not normalized.

The package has no external service dependency. Local tests do not validate role provenance,
application policy correctness, or how the host maps denial to an HTTP/API response.
