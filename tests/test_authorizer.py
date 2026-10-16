# Copyright 2026-present Orbit Contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Authorization and policy immutability tests."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from orbit.errors import ErrorCategory, OrbitError
from orbit_auth import Identity, Principal

from orbit_auth_rbac import PermissionAuthorizer, PermissionDenied, RoleSubject


@dataclass(frozen=True)
class Subject:
    """Framework-independent already-authenticated subject test double."""

    roles: frozenset[str]


def principal(*roles: str) -> Subject:
    """Build a trusted subject with immutable, prevalidated roles."""
    return Subject(roles=frozenset(roles))


def test_permissions_are_the_union_of_exact_role_grants() -> None:
    authorizer = PermissionAuthorizer(
        {"reader": {"catalog.read"}, "editor": {"catalog.write", "catalog.read"}}
    )

    assert authorizer.allows(principal("reader"), "catalog.read")
    assert authorizer.allows(principal("reader", "editor"), "catalog.write")
    assert not authorizer.allows(principal("reader"), "catalog.write")
    assert not authorizer.allows(principal("reader"), "catalog.read.all")


def test_orbit_auth_principal_implements_the_structural_role_subject_contract() -> None:
    authorizer = PermissionAuthorizer({"catalog-editor": {"catalog.read", "catalog.write"}})
    principal = Principal(
        identity=Identity(subject="operator-1", provider="internal"),
        roles=frozenset({"catalog-editor"}),
    )

    assert isinstance(principal, RoleSubject)
    assert authorizer.allows(principal, "catalog.write")


def test_unknown_and_anonymous_roles_default_to_deny() -> None:
    authorizer = PermissionAuthorizer({"reader": {"catalog.read"}})

    assert not authorizer.allows(None, "catalog.read")
    assert not authorizer.allows(principal("unknown"), "catalog.read")
    assert authorizer.permissions_for(None) == frozenset()


def test_grants_are_detached_and_role_inspection_is_deterministic() -> None:
    grants = {"z-role": {"z.read"}, "a-role": {"a.read"}}
    authorizer = PermissionAuthorizer(grants)
    grants["a-role"].clear()
    grants["new-role"] = {"admin.all"}

    assert authorizer.roles == ("a-role", "z-role")
    assert authorizer.allows(principal("a-role"), "a.read")
    assert not authorizer.allows(principal("new-role"), "admin.all")


def test_permission_check_does_not_materialize_the_principal_grant_union(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authorizer = PermissionAuthorizer({"reader": {"catalog.read"}})

    def unexpected_materialization(_principal: RoleSubject | None) -> frozenset[str]:
        raise AssertionError("The membership check must not build the full permission union.")

    monkeypatch.setattr(authorizer, "permissions_for", unexpected_materialization)
    assert authorizer.allows(principal("reader"), "catalog.read")


@pytest.mark.parametrize(
    "grants",
    [
        None,
        {"": {"read"}},
        {"valid": "read"},
        {"valid": {"*"}},
        {"valid": {"bad permission"}},
        {"valid": {"x" * 256}},
    ],
)
def test_rejects_invalid_role_and_permission_configuration(grants: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        PermissionAuthorizer(grants)  # type: ignore[arg-type]


def test_rejects_values_that_do_not_implement_the_subject_contract() -> None:
    authorizer = PermissionAuthorizer({"reader": {"catalog.read"}})
    with pytest.raises(TypeError, match="RoleSubject"):
        authorizer.allows(object(), "catalog.read")  # type: ignore[arg-type]


def test_requires_raises_rbac_denial_without_disclosing_grants_or_permission() -> None:
    authorizer = PermissionAuthorizer({"reader": {"catalog.read"}})

    with pytest.raises(PermissionDenied) as error:
        authorizer.require(principal("reader"), "catalog.write")

    assert error.value.code == "rbac.forbidden"
    assert str(error.value) == "The current subject is not authorized for this operation."
    assert "catalog.write" not in str(error.value)
    assert isinstance(error.value, OrbitError)
    assert isinstance(error.value, PermissionError)
    assert error.value.problem.category is ErrorCategory.SECURITY


def test_subject_must_expose_immutable_bounded_role_identifiers() -> None:
    class MutableSubject:
        roles = {"reader"}

    authorizer = PermissionAuthorizer({"reader": {"catalog.read"}})
    with pytest.raises(TypeError, match="immutable frozenset"):
        authorizer.allows(MutableSubject(), "catalog.read")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="identifiers"):
        authorizer.allows(Subject(roles=frozenset({"bad role"})), "catalog.read")


def test_role_graph_inherits_parent_permissions_transitively_and_is_detached() -> None:
    grants = {
        "reader": {"records.read"},
        "regional-reviewer": {"records.review"},
        "auditor": {"audit.read"},
    }
    inheritance = {
        "regional-reviewer": {"reader"},
        "auditor": {"regional-reviewer"},
    }
    authorizer = PermissionAuthorizer(grants, inherits=inheritance)
    inheritance["auditor"].clear()
    grants["reader"].clear()

    assert authorizer.allows(principal("auditor"), "records.read")
    assert authorizer.allows(principal("auditor"), "records.review")
    assert authorizer.permissions_for(principal("auditor")) == frozenset(
        {"audit.read", "records.read", "records.review"}
    )


@pytest.mark.parametrize(
    "inheritance",
    [
        {"reader": {"undefined"}},
        {"reader": {"editor"}, "editor": {"reader"}},
    ],
)
def test_role_graph_rejects_unknown_parents_and_cycles(inheritance: object) -> None:
    with pytest.raises(ValueError, match="undefined|cycle"):
        PermissionAuthorizer(
            {"reader": {"records.read"}, "editor": {"records.write"}},
            inherits=inheritance,  # type: ignore[arg-type]
        )


def test_attribute_rules_enforce_tenant_and_record_scope_from_verified_claims() -> None:
    authorizer = PermissionAuthorizer(
        {"regional-editor": {"records.update"}},
        attribute_bindings={
            "records.update": {
                "tenant_id": "tenant_id",
                "region_id": "region_id",
            }
        },
    )
    subject = Principal(
        identity=Identity(
            subject="operator-7",
            provider="internal",
            claims={"tenant_id": "tenant-a", "region_id": "north"},
        ),
        roles=frozenset({"regional-editor"}),
    )
    matching_record = {"tenant_id": "tenant-a", "region_id": "north"}

    assert authorizer.allows(subject, "records.update", resource_attributes=matching_record)
    assert not authorizer.allows(
        subject,
        "records.update",
        resource_attributes={"tenant_id": "tenant-b", "region_id": "north"},
    )
    assert not authorizer.allows(
        subject,
        "records.update",
        resource_attributes={"tenant_id": "tenant-a", "region_id": "south"},
    )
    assert not authorizer.allows(subject, "records.update")
    missing_claim = Principal(
        identity=Identity(subject="operator-8", provider="internal"),
        roles=frozenset({"regional-editor"}),
    )
    assert not authorizer.allows(
        missing_claim, "records.update", resource_attributes=matching_record
    )
    assert "records.update" not in authorizer.permissions_for(subject)
    assert authorizer.permissions_for(subject, resource_attributes=matching_record) == frozenset(
        {"records.update"}
    )


def test_attribute_matching_is_typed_and_input_is_bounded() -> None:
    authorizer = PermissionAuthorizer(
        {"editor": {"record.update"}},
        attribute_bindings={"record.update": {"tenant_id": "tenant_id"}},
    )
    subject = Principal(
        identity=Identity(subject="operator", provider="internal", claims={"tenant_id": 1}),
        roles=frozenset({"editor"}),
    )
    assert not authorizer.allows(subject, "record.update", resource_attributes={"tenant_id": True})
    with pytest.raises(TypeError, match="scalar"):
        authorizer.allows(
            subject,
            "record.update",
            resource_attributes={"tenant_id": [1]},
        )


def test_attribute_policy_requires_a_granted_permission_and_valid_identifiers() -> None:
    with pytest.raises(ValueError, match="no role grant"):
        PermissionAuthorizer(
            {"reader": {"records.read"}},
            attribute_bindings={"records.write": {"tenant_id": "tenant_id"}},
        )
    with pytest.raises(ValueError, match="identifiers"):
        PermissionAuthorizer(
            {"reader": {"records.read"}},
            attribute_bindings={"records.read": {"tenant id": "tenant_id"}},
        )
