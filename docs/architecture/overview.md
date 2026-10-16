# Orbit Auth RBAC: architecture

## Role in the authentication stack

`orbit-auth-rbac` evaluates exact permission grants for roles already assigned by a trusted
authentication boundary. It depends on `orbit-auth` for `Principal` and identity contracts and on
Core for its shared structured error contract, but it does not authenticate a request, validate
credentials, or assign roles. A normal
`orbit_auth.Principal` satisfies the structural `RoleSubject` protocol because it exposes validated
immutable roles.

```text
credential/provider adapter
          │ verified identity and trusted roles
          ▼
     orbit-auth Principal ─────► orbit-auth-rbac PermissionAuthorizer
                                             │ exact allow / sanitized denial
                                             ▼
                                  application policy boundary
```

Applications may also pass a custom object with a `frozenset[str]` `roles` property. That object
must be produced by a trusted boundary; structural typing does not authenticate or validate the
origin of the role assignment.

## Policy model

`PermissionAuthorizer` copies the supplied role-to-permission mapping and optional inheritance DAG
into immutable internal maps. Each authorization unions exact permissions from the subject's known
roles and their transitive parents. The directed graph is cycle-checked at construction and
traversed on demand with bounded memory. Unknown roles add no permissions and anonymous subjects
are denied; there are no wildcards or implicit administrator permissions.

Optional `attribute_bindings` apply conjunctive attribute-based checks to selected permissions.
Each binding maps a trusted subject claim key to a resource attribute key. Every configured pair
must be present on both sides and have equal values of the same scalar type. Standard Orbit Auth
`Principal` instances supply claims through `Principal.identity.claims`; a custom `RoleSubject` may
provide an `attributes` mapping. Values that are missing, malformed, or type-mismatched fail closed.

- `allows(subject, permission, resource_attributes=...)` returns a boolean.
- `require(subject, permission, resource_attributes=...)` raises `PermissionDenied` on denial.
- `permissions_for(subject, resource_attributes=...)` returns immutable permissions allowed for
  that specific optional resource context.
- `roles` returns configured role names in deterministic sorted order.

`PermissionDenied` is a generic Core `OrbitError` and `PermissionError` in the security category,
with stable code `rbac.forbidden`; it does not disclose the requested permission or configured
grant map.

## Bounds and identifiers

The policy accepts at most 1,024 roles, at most 4,096 input permission entries per role, and at most
65,536 unique grants and inheritance edges combined. Attribute policies are capped at 4,096
comparisons. Resource and subject attribute mappings are capped at 4,096 entries; compared values
are bounded immutable scalars. Subjects may contain at most 1,024 roles. Each RBAC role and
permission identifier must be 1–255 characters and match `[A-Za-z][A-Za-z0-9_.:-]*`. These bounds
keep construction and per-request membership work predictable. They do not impose a recommended
policy size.

`orbit-auth` accepts a broader role-label syntax. Applications using labels outside the RBAC
identifier grammar must map those trusted labels to bounded RBAC roles during composition rather
than passing arbitrary provider claims directly.

## Lifecycle and dependencies

The package is a synchronous, in-memory policy evaluator with no network client, persistence,
mutable policy API, environment configuration, or shutdown hook. Construct a new authorizer when the
application composes or replaces policy. Direct runtime dependencies are `orbit-auth` and
`orbit-core`.
