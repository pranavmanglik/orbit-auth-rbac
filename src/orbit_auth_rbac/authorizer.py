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
"""Bounded, immutable role-to-permission authorization policies."""

from __future__ import annotations

import re
from collections.abc import Collection, Iterator, Mapping
from math import isfinite
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from orbit.errors import ErrorCategory, OrbitError, OrbitProblem

_MAX_ROLES = 1_024
_MAX_PERMISSIONS_PER_ROLE = 4_096
_MAX_TOTAL_GRANTS = 65_536
_MAX_ATTRIBUTE_RULES = 4_096
_MAX_RESOURCE_ATTRIBUTES = 4_096
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,254}\Z")


@runtime_checkable
class RoleSubject(Protocol):
    """Structural contract for a trusted subject's immutable role identifiers.

    Authentication and role assignment must happen before this object reaches the authorizer.
    Implementations need not inherit from this protocol, but ``roles`` must be a bounded
    ``frozenset[str]`` each time it is read.
    """

    @property
    def roles(self) -> frozenset[str]:
        """Return role identifiers established by a trusted authentication boundary."""


class PermissionDenied(OrbitError, PermissionError):
    """Raise when a subject lacks a requested permission, without disclosing policy contents."""

    code = "rbac.forbidden"
    message = "The current subject is not authorized for this operation."

    def __init__(self) -> None:
        """Create a stable denial error without including the requested permission value."""
        OrbitError.__init__(
            self,
            OrbitProblem(
                code=self.code,
                message=self.message,
                category=ErrorCategory.SECURITY,
            ),
        )


class PermissionAuthorizer:
    """Authorize exact permission identifiers through an immutable role mapping.

    Identity verification and role assignment belong to the application's security capability.
    This package consumes only a trusted subject's immutable role collection. It has no Core
    dependency, persistence, role hierarchy, wildcard matching, or implicit grants: unknown roles
    and permissions are denied.
    """

    def __init__(
        self,
        grants: Mapping[str, Collection[str]],
        *,
        inherits: Mapping[str, Collection[str]] | None = None,
        attribute_bindings: Mapping[str, Mapping[str, str]] | None = None,
    ) -> None:
        """Build a bounded role DAG and resource-attribute equality policy.

        ``inherits`` maps a child role to its direct parent roles. Permission sets flow from a
        parent to each descendant. ``attribute_bindings`` maps a permission to pairs of
        ``subject claim -> resource attribute``; each pair must be present and match before that
        permission is allowed. All policy inputs are detached and immutable after construction.
        """
        if not isinstance(grants, Mapping):
            raise TypeError("RBAC grants must be a mapping of roles to permission collections.")

        normalized: dict[str, frozenset[str]] = {}
        total_grants = 0
        for index, (role, permissions) in enumerate(grants.items(), start=1):
            if index > _MAX_ROLES:
                raise ValueError(f"RBAC policies cannot contain more than {_MAX_ROLES:,} roles.")
            normalized_role = _validate_identifier(role, kind="role")
            if normalized_role in normalized:
                raise ValueError(f"RBAC role {normalized_role!r} is defined more than once.")
            if isinstance(permissions, (str, bytes)) or not isinstance(permissions, Collection):
                raise TypeError("Each role must map to a collection of permissions.")

            normalized_permissions: set[str] = set()
            for permission_index, permission in enumerate(permissions, start=1):
                if permission_index > _MAX_PERMISSIONS_PER_ROLE:
                    raise ValueError(
                        "An RBAC role cannot contain more than "
                        f"{_MAX_PERMISSIONS_PER_ROLE:,} permissions."
                    )
                normalized_permissions.add(_validate_identifier(permission, kind="permission"))
            total_grants += len(normalized_permissions)
            if total_grants > _MAX_TOTAL_GRANTS:
                raise ValueError(
                    f"RBAC policies cannot contain more than {_MAX_TOTAL_GRANTS:,} grants."
                )
            normalized[normalized_role] = frozenset(normalized_permissions)

        parent_map = self._validated_parent_map(normalized, inherits, grant_count=total_grants)
        self._validate_acyclic(parent_map)
        self._parents = MappingProxyType(parent_map)
        self._grants = MappingProxyType(normalized)
        self._attribute_bindings = MappingProxyType(
            self._validated_attribute_bindings(normalized, attribute_bindings)
        )

    @staticmethod
    def _validated_parent_map(
        grants: Mapping[str, frozenset[str]],
        inherits: Mapping[str, Collection[str]] | None,
        *,
        grant_count: int,
    ) -> dict[str, frozenset[str]]:
        """Validate graph nodes and bound inheritance edges before resolving transitive roles."""
        if inherits is None:
            return {role: frozenset() for role in grants}
        if not isinstance(inherits, Mapping):
            raise TypeError("RBAC inheritance must map roles to parent-role collections.")
        unknown_children = set(inherits) - grants.keys()
        if unknown_children:
            raise ValueError("RBAC inheritance contains an undefined child role.")
        parents: dict[str, frozenset[str]] = {role: frozenset() for role in grants}
        edge_count = 0
        for child, values in inherits.items():
            _validate_identifier(child, kind="role")
            if isinstance(values, (str, bytes)) or not isinstance(values, Collection):
                raise TypeError("Each inherited role must map to a collection of parent roles.")
            if len(values) > _MAX_ROLES:
                raise ValueError("An RBAC role cannot inherit more than 1,024 parent roles.")
            selected = {_validate_identifier(parent, kind="role") for parent in values}
            if child in selected:
                raise ValueError("RBAC role inheritance cannot contain a cycle.")
            if selected - grants.keys():
                raise ValueError("RBAC inheritance references an undefined parent role.")
            edge_count += len(selected)
            if grant_count + edge_count > _MAX_TOTAL_GRANTS:
                raise ValueError(
                    "RBAC grants and inheritance edges exceed the configured combined bound."
                )
            parents[child] = frozenset(selected)
        return parents

    @staticmethod
    def _validate_acyclic(parents: Mapping[str, frozenset[str]]) -> None:
        """Reject directed cycles in linear graph traversal without storing a closure matrix."""
        visited: set[str] = set()
        for root in parents:
            if root in visited:
                continue
            active: set[str] = set()
            stack: list[tuple[str, Iterator[str]]] = [(root, iter(parents[root]))]
            active.add(root)
            while stack:
                role, iterator = stack[-1]
                try:
                    parent = next(iterator)
                except StopIteration:
                    stack.pop()
                    active.remove(role)
                    visited.add(role)
                    continue
                if parent in active:
                    raise ValueError("RBAC role inheritance graph cannot contain a cycle.")
                if parent not in visited:
                    active.add(parent)
                    stack.append((parent, iter(parents[parent])))

    @staticmethod
    def _validated_attribute_bindings(
        grants: Mapping[str, frozenset[str]],
        policies: Mapping[str, Mapping[str, str]] | None,
    ) -> dict[str, Mapping[str, str]]:
        """Validate permission-to-claim/resource comparisons and freeze the policy graph."""
        if policies is None:
            return {}
        if not isinstance(policies, Mapping):
            raise TypeError("RBAC attribute bindings must be a mapping.")
        result: dict[str, Mapping[str, str]] = {}
        rule_count = 0
        for permission, bindings in policies.items():
            normalized_permission = _validate_identifier(permission, kind="permission")
            if not isinstance(bindings, Mapping) or not bindings:
                raise TypeError("Each attribute-bound permission must have a non-empty mapping.")
            if not any(normalized_permission in values for values in grants.values()):
                raise ValueError("Attribute bindings reference a permission with no role grant.")
            normalized: dict[str, str] = {}
            for subject_key, resource_key in bindings.items():
                normalized_subject = _validate_identifier(subject_key, kind="subject attribute")
                normalized_resource = _validate_identifier(resource_key, kind="resource attribute")
                normalized[normalized_subject] = normalized_resource
            rule_count += len(normalized)
            if rule_count > _MAX_ATTRIBUTE_RULES:
                raise ValueError("RBAC attribute bindings exceed the configured rule bound.")
            result[normalized_permission] = MappingProxyType(normalized)
        return result

    @property
    def roles(self) -> tuple[str, ...]:
        """Return the configured role names in deterministic order."""
        return tuple(sorted(self._grants))

    def permissions_for(
        self,
        subject: RoleSubject | None,
        *,
        resource_attributes: Mapping[str, object] | None = None,
    ) -> frozenset[str]:
        """Return the permissions allowed for the subject and optional resource attributes.

        Parent-role grants are inherited transitively. Attribute-constrained permissions are
        omitted unless every configured subject claim matches its resource field. The returned
        set is detached and immutable.
        """
        roles = _roles_for(subject)
        if roles is None:
            return frozenset()
        effective_roles = self._effective_roles(roles)
        permissions: set[str] = set()
        for role in effective_roles:
            permissions.update(self._grants.get(role, ()))
        if self._attribute_bindings:
            attributes = _resource_attributes(resource_attributes)
            subject_attributes = _subject_attributes(subject)
            permissions = {
                permission
                for permission in permissions
                if self._attributes_match(permission, subject_attributes, attributes)
            }
        return frozenset(permissions)

    def _effective_roles(self, roles: frozenset[str]) -> set[str]:
        """Resolve a subject's role ancestry on demand with bounded graph traversal."""
        effective = set(roles)
        pending = list(roles)
        while pending:
            current = pending.pop()
            for parent in self._parents.get(current, ()):
                if parent not in effective:
                    effective.add(parent)
                    pending.append(parent)
        return effective

    def allows(
        self,
        subject: RoleSubject | None,
        permission: str,
        *,
        resource_attributes: Mapping[str, object] | None = None,
    ) -> bool:
        """Check one exact inherited permission and any configured resource-attribute rules."""
        normalized_permission = _validate_identifier(permission, kind="permission")
        return self._allows_validated(subject, normalized_permission, resource_attributes)

    def _allows_validated(
        self,
        subject: RoleSubject | None,
        permission: str,
        resource_attributes: Mapping[str, object] | None = None,
    ) -> bool:
        """Check a single grant without materializing every permission in the subject's roles."""
        roles = _roles_for(subject)
        if roles is None:
            return False
        permitted_roles = self._effective_roles(roles)
        if not any(permission in self._grants.get(role, ()) for role in permitted_roles):
            return False
        if permission not in self._attribute_bindings:
            return True
        return self._attributes_match(
            permission,
            _subject_attributes(subject),
            _resource_attributes(resource_attributes),
        )

    def _attributes_match(
        self,
        permission: str,
        subject: Mapping[str, object],
        resource: Mapping[str, object],
    ) -> bool:
        """Require typed, present equality for each trusted claim/resource-field binding."""
        bindings = self._attribute_bindings.get(permission)
        if bindings is None:
            return True
        for subject_key, resource_key in bindings.items():
            if subject_key not in subject or resource_key not in resource:
                return False
            left, right = subject[subject_key], resource[resource_key]
            if not _is_attribute_scalar(left) or not _is_attribute_scalar(right):
                return False
            if (isinstance(left, float) and not isfinite(left)) or (
                isinstance(right, float) and not isfinite(right)
            ):
                return False
            if type(left) is not type(right) or left != right:
                return False
        return True

    def require(
        self,
        subject: RoleSubject | None,
        permission: str,
        *,
        resource_attributes: Mapping[str, object] | None = None,
    ) -> None:
        """Raise a sanitized package-level denial unless the subject has the permission."""
        normalized_permission = _validate_identifier(permission, kind="permission")
        if not self._allows_validated(subject, normalized_permission, resource_attributes):
            raise PermissionDenied


def _validate_identifier(value: object, *, kind: str) -> str:
    """Validate one bounded, control-free role or permission identifier."""
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(
            f"RBAC {kind} identifiers must start with a letter and contain only "
            "letters, digits, underscore, dot, colon, or hyphen (up to 255 characters)."
        )
    return value


def _roles_for(subject: RoleSubject | None) -> frozenset[str] | None:
    """Validate and detach role identifiers from one trusted structural subject."""
    if subject is None:
        return None
    if not isinstance(subject, RoleSubject):
        raise TypeError("subject must implement the RoleSubject contract or be None.")
    roles = subject.roles
    if not isinstance(roles, frozenset):
        raise TypeError("RoleSubject.roles must be an immutable frozenset of identifiers.")
    if len(roles) > _MAX_ROLES:
        raise ValueError(f"A subject cannot contain more than {_MAX_ROLES:,} roles.")
    for role in roles:
        _validate_identifier(role, kind="role")
    return roles


def _subject_attributes(subject: RoleSubject | None) -> Mapping[str, object]:
    """Read trusted attributes from an explicit subject mapping or Orbit Auth identity claims."""
    if subject is None:
        return MappingProxyType({})
    attributes = getattr(subject, "attributes", None)
    if attributes is None:
        attributes = getattr(getattr(subject, "identity", None), "claims", None)
    if attributes is None:
        return MappingProxyType({})
    if not isinstance(attributes, Mapping):
        raise TypeError("Trusted subject attributes must be a mapping.")
    if len(attributes) > _MAX_RESOURCE_ATTRIBUTES:
        raise ValueError("Trusted subject attributes exceed the configured bound.")
    return attributes


def _resource_attributes(
    attributes: Mapping[str, object] | None,
) -> Mapping[str, object]:
    """Validate a bounded resource context containing only JSON-like scalar comparisons."""
    if attributes is None:
        return MappingProxyType({})
    if not isinstance(attributes, Mapping):
        raise TypeError("Resource attributes must be a mapping or None.")
    if len(attributes) > _MAX_RESOURCE_ATTRIBUTES:
        raise ValueError("Resource attributes exceed the configured bound.")
    validated: dict[str, object] = {}
    for key, value in attributes.items():
        validated_key = _validate_identifier(key, kind="resource attribute")
        if not _is_attribute_scalar(value):
            raise TypeError("Resource attributes must contain bounded scalar values.")
        validated[validated_key] = value
    return validated


def _is_attribute_scalar(value: object) -> bool:
    """Limit trusted claim comparisons to immutable scalar values with stable equality."""
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, str):
        return len(value) <= 4_096
    if isinstance(value, int):
        return value.bit_length() <= 64
    return isinstance(value, float) and isfinite(value)


__all__ = ["PermissionAuthorizer", "PermissionDenied", "RoleSubject"]
