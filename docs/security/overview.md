# Orbit Auth RBAC: security

This package makes authorization decisions from a role set and optional resource context supplied
by its caller. It does not verify identity, validate a credential, establish that roles came from a
trusted provider, or protect a network endpoint. Authorization is only as trustworthy as the
subject and server-loaded resource context passed to it.

## Trust the source of roles

- Pass an `orbit-auth.Principal` created by a verified authentication flow, or a custom
  `RoleSubject` populated from equivalent trusted server-side state.
- Do not construct roles from query parameters, request bodies, unverified JWT claims, or arbitrary
  browser input.
- Treat role assignment as a separate policy decision. A valid permission mapping cannot correct
  an attacker-controlled role assignment.
- The structural protocol checks that `roles` is a `frozenset` of valid role identifiers; it cannot
  establish who created that set.

## Define narrow grants

Permissions are matched exactly. A grant for `catalog.read` does not imply `catalog.read.all`.
Optional role inheritance is a reviewed, cycle-checked DAG: permissions flow from parent to child,
so granting a parent role expands every descendant's access. Review graph changes as security-
sensitive. Unknown roles and anonymous subjects default to denial. Do not interpret
`PermissionAuthorizer.roles` or `permissions_for()` as proof that a caller is authenticated; they
only describe configured/effective grants.

Attribute bindings require all selected subject claims to equal attributes from a trusted,
server-loaded resource. This supports tenant and row-level authorization, such as requiring both
`tenant_id` and `region_id` to match. Never pass request-supplied resource attributes as proof of
record ownership. Load the record first, then authorize using its trusted fields. Missing values,
non-scalar data, and cross-type equalities fail closed.

RBAC accepts a narrower identifier grammar than `orbit-auth` role labels. Map provider role claims
to reviewed local roles when the original value does not fit the RBAC grammar. Do not normalize
untrusted input into a powerful role name.

## Denial and logging

`PermissionDenied` is a Core structured security error with a generic message and stable
`rbac.forbidden` code. Map it to the host application's forbidden response without returning the
grant map or requested permission to an untrusted caller. Avoid logging complete subject claims or
sensitive permission names when they reveal internal resources.

This evaluator is local and immutable after construction. It has no role database, policy reload,
revocation propagation, or distributed cache. Construct and inject a replacement authorizer when
the grant policy changes, and have the trusted authentication boundary refresh role data when role
assignments change. Coordinate each update across application workers.

## Vulnerability reporting

Use the repository [security policy](../../SECURITY.md) for private vulnerability reports.
