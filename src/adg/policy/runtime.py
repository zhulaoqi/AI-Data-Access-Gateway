from dataclasses import dataclass, field

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.control_plane.models.directory import Role, User, UserRole
from adg.control_plane.models.governance import FieldPolicy, ResourcePolicy, ResourceTag
from adg.control_plane.models.resource import Resource
from adg_ext import hooks as ext_hooks


@dataclass(frozen=True)
class IdentityContext:
    """Key-derived runtime identity used during policy and audit evaluation."""

    user_id: str | None
    roles: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    org_node_id: str | None = None

    @property
    def role_ids(self) -> list[str]:
        """Expose role identifiers with the new directory-driven naming."""

        return self.roles


def load_runtime_identity_for_user(
    session: Session,
    *,
    user_id: str | None,
) -> IdentityContext:
    """Load one runtime identity from a user binding on an authenticated API key."""

    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Runtime key must be bound to a user",
        )

    user = session.execute(
        select(User).where(User.id == user_id, User.status == "active")
    ).scalar_one_or_none()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Runtime key user was not found",
        )

    role_ids = list(
        session.execute(
            select(Role.id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(
                UserRole.user_id == user.id,
                Role.status == "active",
            )
            .order_by(Role.id)
        ).scalars()
    )
    return IdentityContext(
        user_id=user.id,
        roles=role_ids,
        org_node_id=user.org_node_id,
    )


@dataclass(frozen=True)
class PolicyDecision:
    """Policy evaluation result with a stable machine-readable reason."""

    allowed: bool
    reason: str


class RuntimePolicyService:
    """Evaluates resource and field access against active governance policies."""

    _RESOURCE_SPECIFICITY = {
        "relational_table": 4,
        "relational_view": 4,
        "schema": 3,
        "database": 2,
        "datasource": 1,
    }

    def __init__(self, session: Session) -> None:
        self._session = session

    def check_resource_access(
        self,
        *,
        identity: IdentityContext,
        resource: Resource,
        action: str,
    ) -> PolicyDecision:
        """Decide whether an identity may perform an action on a resource."""

        self._session.flush()
        policies = self._resource_policies(identity=identity, action=action)
        if not policies:
            return PolicyDecision(allowed=False, reason="no_policy_default_deny")

        matching = self._matching_resource_policies(
            policies=policies,
            identity=identity,
            resource=resource,
        )
        if any(policy.effect == "deny" for policy in matching):
            return PolicyDecision(allowed=False, reason="denied_by_policy")
        if any(policy.effect == "allow" for policy in matching):
            return PolicyDecision(allowed=True, reason="allowed_by_policy")
        return PolicyDecision(allowed=False, reason="no_matching_allow")

    def check_resource_access_batch(
        self,
        *,
        identity: IdentityContext,
        resources: list[Resource],
        action: str,
    ) -> dict[str, PolicyDecision]:
        """Decide access for many resources after preloading shared policy context."""

        self._session.flush()
        if not resources:
            return {}

        policies = self._resource_policies(identity=identity, action=action)
        if not policies:
            return {
                resource.id: PolicyDecision(allowed=False, reason="no_policy_default_deny")
                for resource in resources
            }

        resource_chains = self._resource_scope_chains(resources)
        tag_ids_by_resource_id = self._resource_tag_ids_by_resource_id(
            resources=resources,
            policies=policies,
        )
        decisions: dict[str, PolicyDecision] = {}
        for resource in resources:
            matching = self._matching_resource_policies(
                policies=policies,
                identity=identity,
                resource=resource,
                resource_chain=resource_chains[resource.id],
                tag_ids_by_resource_id=tag_ids_by_resource_id,
            )
            if any(policy.effect == "deny" for policy in matching):
                decisions[resource.id] = PolicyDecision(allowed=False, reason="denied_by_policy")
            elif any(policy.effect == "allow" for policy in matching):
                decisions[resource.id] = PolicyDecision(allowed=True, reason="allowed_by_policy")
            else:
                decisions[resource.id] = PolicyDecision(allowed=False, reason="no_matching_allow")
        return decisions
    def check_decrypt_access(
        self,
        *,
        identity: IdentityContext,
        resource: Resource,
    ) -> PolicyDecision:
        """Decide whether an identity may decrypt masked values for a resource."""

        self._session.flush()
        policies = self._resource_policies(identity=identity, action="read")
        if not policies:
            return PolicyDecision(allowed=False, reason="no_policy_default_deny")

        matching = self._matching_resource_policies(
            policies=policies,
            identity=identity,
            resource=resource,
        )
        if any(policy.effect == "deny" for policy in matching):
            return PolicyDecision(allowed=False, reason="denied_by_policy")
        if any(policy.effect == "allow" and policy.allow_decrypt for policy in matching):
            return PolicyDecision(allowed=True, reason="allowed_by_policy")
        return PolicyDecision(allowed=False, reason="decrypt_not_allowed")

    def check_field_access(
        self,
        *,
        identity: IdentityContext,
        resource: Resource,
        field_name: str,
        action: str,
    ) -> PolicyDecision:
        """Decide field-level access after the parent resource has already been allowed."""

        self._session.flush()
        if ext_hooks.field_denied(self._session, identity, resource.id, field_name):
            return PolicyDecision(allowed=False, reason="field_not_in_scope")
        policies = list(
            self._session.execute(
                select(FieldPolicy).where(
                    FieldPolicy.status == "active",
                    FieldPolicy.action == action,
                    FieldPolicy.resource_id == resource.id,
                    FieldPolicy.field_name == field_name,
                )
            ).scalars()
        )
        return self._field_policy_decision(policies=policies, identity=identity)

    def first_inaccessible_field(
        self,
        *,
        identity: IdentityContext,
        resources: list[Resource],
        field_names: list[str],
        action: str,
    ) -> str | None:
        """Return the first field denied by active field policies using one policy query."""

        self._session.flush()
        if not resources or not field_names:
            return None

        resource_ids = [resource.id for resource in resources]
        policies = list(
            self._session.execute(
                select(FieldPolicy).where(
                    FieldPolicy.status == "active",
                    FieldPolicy.action == action,
                    FieldPolicy.resource_id.in_(resource_ids),
                    FieldPolicy.field_name.in_(field_names),
                )
            ).scalars()
        )
        policies_by_scope: dict[tuple[str, str], list[FieldPolicy]] = {}
        for policy in policies:
            key = (policy.resource_id, policy.field_name)
            policies_by_scope.setdefault(key, []).append(policy)

        for resource in resources:
            for field_name in field_names:
                if ext_hooks.field_denied(self._session, identity, resource.id, field_name):
                    return field_name
                decision = self._field_policy_decision(
                    policies=policies_by_scope.get((resource.id, field_name), []),
                    identity=identity,
                )
                if not decision.allowed:
                    return field_name
        return None

    def _field_policy_decision(
        self,
        *,
        policies: list[FieldPolicy],
        identity: IdentityContext,
    ) -> PolicyDecision:
        """Evaluate already-loaded policies for one field scope."""

        subject_policies = [
            policy for policy in policies if self._subject_matches(policy, identity)
        ]
        if any(policy.effect == "deny" for policy in subject_policies):
            return PolicyDecision(allowed=False, reason="denied_by_policy")
        if any(policy.effect == "allow" for policy in subject_policies):
            return PolicyDecision(allowed=True, reason="allowed_by_policy")
        # Field policy presence switches the field from default-allow to require matching allow.
        if policies:
            return PolicyDecision(allowed=False, reason="no_matching_allow")
        return PolicyDecision(allowed=True, reason="no_policy")

    def _resource_policies(
        self,
        *,
        identity: IdentityContext,
        action: str,
    ) -> list[ResourcePolicy]:
        """Load active policies for one action before subject/resource filtering."""

        return list(
            self._session.execute(
                select(ResourcePolicy).where(
                    ResourcePolicy.status == "active",
                    ResourcePolicy.action == action,
                )
            ).scalars()
        )

    def _resource_policy_matches(self, policy: ResourcePolicy, resource: Resource) -> bool:
        """Match a policy to a resource directly, through a tag, or globally."""

        if policy.resource_id is not None:
            return policy.resource_id == resource.id
        if policy.datasource_id is not None:
            return policy.datasource_id == resource.datasource_id
        if policy.tag_id is not None:
            return (
                self._session.execute(
                    select(ResourceTag).where(
                        ResourceTag.resource_id == resource.id,
                        ResourceTag.tag_id == policy.tag_id,
                    )
                ).scalar_one_or_none()
                is not None
            )
        return True

    def _subject_matches(
        self,
        policy: ResourcePolicy | FieldPolicy,
        identity: IdentityContext,
    ) -> bool:
        """Match a policy subject selector against the runtime identity."""

        if policy.subject_type == "all":
            return True
        if policy.subject_type == "user":
            return policy.subject_id == identity.user_id
        if policy.subject_type == "role":
            return policy.subject_id in identity.roles
        return False

    def _matching_resource_policies(
        self,
        *,
        policies: list[ResourcePolicy],
        identity: IdentityContext,
        resource: Resource,
        resource_chain: list[Resource] | None = None,
        tag_ids_by_resource_id: dict[str, set[str]] | None = None,
    ) -> list[ResourcePolicy]:
        """Return subject-matching policies from the most specific matching resource scope."""

        if resource_chain is None:
            resource_chain = self._resource_scope_chain(resource)
        matched: list[tuple[int, ResourcePolicy]] = []
        for policy in policies:
            if not self._subject_matches(policy, identity):
                continue
            specificity = self._resource_policy_specificity(
                policy=policy,
                resource=resource,
                resource_chain=resource_chain,
                tag_ids_by_resource_id=tag_ids_by_resource_id,
            )
            if specificity is None:
                continue
            matched.append((specificity, policy))
        if not matched:
            return []
        highest_specificity = max(specificity for specificity, _ in matched)
        return [
            policy for specificity, policy in matched if specificity == highest_specificity
        ]

    def _resource_policy_specificity(
        self,
        *,
        policy: ResourcePolicy,
        resource: Resource,
        resource_chain: list[Resource],
        tag_ids_by_resource_id: dict[str, set[str]] | None = None,
    ) -> int | None:
        """Return one sortable specificity score when a policy applies to a resource."""

        if policy.resource_id is not None:
            for current in resource_chain:
                if current.id == policy.resource_id:
                    return self._RESOURCE_SPECIFICITY.get(current.kind, 1)
            return None
        if policy.datasource_id is not None:
            return 1 if policy.datasource_id == resource.datasource_id else None
        if policy.tag_id is not None:
            if tag_ids_by_resource_id is not None:
                resource_tag_ids = tag_ids_by_resource_id.get(resource.id, set())
                return 1 if policy.tag_id in resource_tag_ids else None
            matches = (
                self._session.execute(
                    select(ResourceTag).where(
                        ResourceTag.resource_id == resource.id,
                        ResourceTag.tag_id == policy.tag_id,
                    )
                ).scalar_one_or_none()
                is not None
            )
            return 1 if matches else None
        return 0

    def _resource_scope_chains(self, resources: list[Resource]) -> dict[str, list[Resource]]:
        """Return resource ancestry for many resources after batched parent loading."""

        resources_by_id = {resource.id: resource for resource in resources}
        pending_parent_ids = {
            resource.parent_id
            for resource in resources
            if resource.parent_id is not None and resource.parent_id not in resources_by_id
        }
        while pending_parent_ids:
            parents = list(
                self._session.execute(
                    select(Resource).where(Resource.id.in_(sorted(pending_parent_ids)))
                ).scalars()
            )
            if not parents:
                break
            pending_parent_ids = set()
            for parent in parents:
                resources_by_id[parent.id] = parent
                if parent.parent_id is not None and parent.parent_id not in resources_by_id:
                    pending_parent_ids.add(parent.parent_id)

        chains: dict[str, list[Resource]] = {}
        for resource in resources:
            chain = [resource]
            current = resource
            seen_ids = {resource.id}
            while current.parent_id is not None:
                next_parent = resources_by_id.get(current.parent_id)
                if next_parent is None or next_parent.id in seen_ids:
                    break
                chain.append(next_parent)
                seen_ids.add(next_parent.id)
                current = next_parent
            chains[resource.id] = chain
        return chains

    def _resource_tag_ids_by_resource_id(
        self,
        *,
        resources: list[Resource],
        policies: list[ResourcePolicy],
    ) -> dict[str, set[str]]:
        """Load only policy-relevant tag bindings for many resources."""

        policy_tag_ids = sorted({policy.tag_id for policy in policies if policy.tag_id is not None})
        if not resources or not policy_tag_ids:
            return {}

        resource_ids = [resource.id for resource in resources]
        rows = self._session.execute(
            select(ResourceTag.resource_id, ResourceTag.tag_id).where(
                ResourceTag.resource_id.in_(resource_ids),
                ResourceTag.tag_id.in_(policy_tag_ids),
            )
        ).all()
        tag_ids_by_resource_id: dict[str, set[str]] = {
            resource_id: set() for resource_id in resource_ids
        }
        for resource_id, tag_id in rows:
            tag_ids_by_resource_id.setdefault(resource_id, set()).add(tag_id)
        return tag_ids_by_resource_id
    def _resource_scope_chain(self, resource: Resource) -> list[Resource]:
        """Return one resource followed by its ancestors up to the datasource root."""

        chain = [resource]
        current = resource
        while current.parent_id is not None:
            parent = self._session.get(Resource, current.parent_id)
            if parent is None:
                break
            chain.append(parent)
            current = parent
        return chain
