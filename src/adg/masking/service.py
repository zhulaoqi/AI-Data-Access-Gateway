import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from adg.connectors.base import QueryResult
from adg.control_plane.models.masking import DecryptContext, MaskingPolicy
from adg.control_plane.models.resource import Resource
from adg.policy.runtime import IdentityContext
from adg.shared.crypto import (
    decrypt_fernet_envelope,
    decrypt_legacy_fernet_token,
    encrypt_fernet_envelope,
    envelope_from_json,
    envelope_to_json,
)
from adg.shared.errors import ValidationError
from adg.shared.ids import uuidv7
from adg.sql_guard.guard import ProjectionLineage


class MaskingService:
    """Applies masking policies and manages reversible decrypt contexts."""

    def __init__(
        self,
        session: Session,
        *,
        secret_key: str,
        masking_encryption_key: str | None = None,
        kdf_iterations: int = 390_000,
    ) -> None:
        """Create a masking service using service-level encryption keys."""

        self._session = session
        self._secret_key = secret_key
        self._masking_encryption_key = masking_encryption_key or secret_key
        self._kdf_iterations = kdf_iterations

    def apply_to_result(
        self,
        *,
        identity: IdentityContext,
        datasource_id: str,
        query_id: str,
        resources: list[Resource],
        result: QueryResult,
        projections: list[ProjectionLineage] | None = None,
    ) -> tuple[QueryResult, list[dict[str, str]]]:
        """Return a masked query result plus metadata about changed columns."""

        policies = self._matching_policies(identity=identity, resources=resources)
        policy_targets = [
            (policy, output_name)
            for policy in policies
            for output_name in self._policy_output_names(policy, projections)
        ]
        masked_columns: list[dict[str, str]] = []
        rows: list[dict[str, object]] = []
        reversible_fields = sorted(
            {
                output_name
                for policy, output_name in policy_targets
                if policy.strategy == "reversible"
                and any(self._row_value(row, output_name) is not None for row in result.rows)
            }
        )
        reversible_context = None
        if reversible_fields:
            reversible_context = self._create_reversible_context(
                user_id=identity.user_id,
                datasource_id=datasource_id,
                resource_ids=[resource.id for resource in resources],
                query_id=query_id,
                field_names=reversible_fields,
            )

        for row in result.rows:
            masked_row = dict(row)
            for policy, output_name in policy_targets:
                row_key = self._row_key(masked_row, output_name)
                if row_key is None or masked_row[row_key] is None:
                    continue
                # Reversible masking stores a decrypt context; other strategies are stateless.
                if policy.strategy == "reversible":
                    if reversible_context is None:
                        raise RuntimeError("Reversible masking context was not initialized")
                    context_id, temporary_fernet = reversible_context
                    masked_row[row_key] = self._encrypt_reversible_marker(
                        context_id=context_id,
                        temporary_fernet=temporary_fernet,
                        value=masked_row[row_key],
                    )
                else:
                    masked_row[row_key] = self.mask_plain_value(
                        masked_row[row_key],
                        strategy=policy.strategy,
                        config=self._policy_config(policy),
                    )
                marker = {"name": row_key, "strategy": policy.strategy}
                if marker not in masked_columns:
                    masked_columns.append(marker)
            rows.append(masked_row)

        return QueryResult(columns=result.columns, rows=rows), masked_columns

    def projection_rejection(
        self,
        *,
        identity: IdentityContext,
        resources: list[Resource],
        projections: list[ProjectionLineage],
    ) -> str | None:
        """Reject projections that combine more than one applicable masking policy."""

        policies = self._matching_policies(identity=identity, resources=resources)
        if policies and any(projection.is_wildcard for projection in projections):
            return "masked_wildcard_projection_not_allowed"
        if policies and any(projection.has_nested_select for projection in projections):
            return "masked_nested_projection_not_supported"
        for projection in projections:
            source_fields = {field.casefold() for field in projection.source_fields}
            matching = [
                policy for policy in policies if policy.field_name.casefold() in source_fields
            ]
            if matching and projection.output_name is None:
                return "masked_projection_requires_alias"
            if len(matching) > 1:
                return "ambiguous_masking_projection"
        return None

    def mask_plain_value(
        self,
        value: object,
        *,
        strategy: str,
        config: dict[str, object],
    ) -> str | None:
        """Mask a scalar value using a non-reversible strategy."""

        if value is None:
            return None
        text = str(value)
        if strategy == "null":
            return None
        if strategy == "fixed":
            return str(config.get("replacement", "***"))
        if strategy == "partial":
            prefix = int(str(config.get("prefix", 2)))
            suffix = int(str(config.get("suffix", 2)))
            fill = str(config.get("fill", "*"))[:1] or "*"
            # When the visible prefix and suffix would overlap, hide the whole value.
            if len(text) <= prefix + suffix:
                return fill * len(text)
            return f"{text[:prefix]}{fill * (len(text) - prefix - suffix)}{text[-suffix:]}"
        if strategy == "hash":
            return hashlib.sha256(f"{self._secret_key}:{text}".encode()).hexdigest()
        raise ValidationError(f"Unsupported masking strategy: {strategy}")

    def mask_reversible_value(
        self,
        *,
        user_id: str | None,
        datasource_id: str,
        resource_ids: list[str] | None = None,
        query_id: str,
        field_name: str,
        value: object,
        expires_at: datetime | None = None,
    ) -> str:
        """Encrypt one value and return an ADG marker that can be decrypted later."""

        context_id, temporary_fernet = self._create_reversible_context(
            user_id=user_id,
            datasource_id=datasource_id,
            resource_ids=resource_ids or [],
            query_id=query_id,
            field_names=[field_name],
            expires_at=expires_at,
        )
        return self._encrypt_reversible_marker(
            context_id=context_id,
            temporary_fernet=temporary_fernet,
            value=value,
        )

    def _create_reversible_context(
        self,
        *,
        user_id: str | None,
        datasource_id: str,
        resource_ids: list[str],
        query_id: str,
        field_names: list[str],
        expires_at: datetime | None = None,
    ) -> tuple[str, Fernet]:
        """Create one temporary key and decrypt context for a reversible result batch."""

        context_id = uuidv7()
        temporary_key = Fernet.generate_key()
        temporary_fernet = Fernet(temporary_key)
        context = DecryptContext(
            id=context_id,
            query_id=query_id,
            user_id=user_id,
            datasource_id=datasource_id,
            resource_ids_json=json.dumps(resource_ids, separators=(",", ":")),
            key_ciphertext=envelope_to_json(
                encrypt_fernet_envelope(
                    temporary_key,
                    secret=self._masking_encryption_key,
                    iterations=self._kdf_iterations,
                )
            ),
            allowed_fields_json=json.dumps(field_names, separators=(",", ":")),
            expires_at=expires_at or datetime.now(UTC) + timedelta(minutes=15),
        )
        self._session.add(context)
        self._session.flush()
        return context_id, temporary_fernet

    def _encrypt_reversible_marker(
        self,
        *,
        context_id: str,
        temporary_fernet: Fernet,
        value: object,
    ) -> str:
        """Encrypt one scalar with an already-created reversible result context."""

        ciphertext = temporary_fernet.encrypt(str(value).encode()).decode()
        return f"$adg_rev${context_id}${ciphertext}"

    def decrypt_values(
        self,
        *,
        user_id: str | None,
        values: list[str],
    ) -> list[str]:
        """Decrypt a batch of reversible ADG markers for the requesting user."""

        context_fernets: dict[str, Fernet] = {}
        plaintext: list[str] = []
        for marker in values:
            context_id, ciphertext = self._parse_marker(marker)
            temporary_fernet = context_fernets.get(context_id)
            if temporary_fernet is None:
                context = self._get_decrypt_context(user_id=user_id, marker=marker)
                try:
                    temporary_fernet = Fernet(
                        self._decrypt_context_key(context.key_ciphertext)
                    )
                except InvalidToken as error:
                    raise ValidationError("Decrypt value is invalid") from error
                context_fernets[context_id] = temporary_fernet
            try:
                plaintext.append(temporary_fernet.decrypt(ciphertext.encode()).decode())
            except InvalidToken as error:
                raise ValidationError("Decrypt value is invalid") from error
        return plaintext

    def get_decrypt_contexts(
        self,
        *,
        user_id: str | None,
        values: list[str],
    ) -> list[DecryptContext]:
        """Resolve reversible markers into validated decrypt contexts."""

        return [self._get_decrypt_context(user_id=user_id, marker=value) for value in values]

    def _get_decrypt_context(self, *, user_id: str | None, marker: str) -> DecryptContext:
        """Load one decrypt context and enforce identity and TTL validation."""

        context_id, _ = self._parse_marker(marker)
        context = self._session.get(DecryptContext, context_id)
        if context is None:
            raise ValidationError("Decrypt context not found")
        if context.user_id != user_id:
            raise ValidationError("Decrypt context does not match identity")
        if self._normalize_time(context.expires_at) <= datetime.now(UTC):
            raise ValidationError("Decrypt context expired")
        return context

    def _parse_marker(self, marker: str) -> tuple[str, str]:
        """Parse the reversible marker format into context id and ciphertext."""

        parts = marker.split("$", 3)
        if len(parts) != 4 or parts[0] != "" or parts[1] != "adg_rev":
            raise ValidationError("Invalid reversible value marker")
        return parts[2], parts[3]

    def _decrypt_context_key(self, key_ciphertext: str) -> bytes:
        """Decrypt a reversible masking context key from v2 or legacy storage."""

        envelope = envelope_from_json(key_ciphertext)
        if envelope is not None:
            return decrypt_fernet_envelope(
                envelope,
                secret=self._masking_encryption_key,
                legacy_secrets=(self._secret_key,),
            )
        return decrypt_legacy_fernet_token(
            key_ciphertext,
            secrets=(self._masking_encryption_key, self._secret_key),
        )

    def _normalize_time(self, value: datetime) -> datetime:
        """Treat stored naive timestamps as UTC for consistent TTL checks."""

        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value

    def _matching_policies(
        self,
        *,
        identity: IdentityContext,
        resources: list[Resource],
    ) -> list[MaskingPolicy]:
        """Load active masking policies that apply to the queried resources and identity."""

        resource_ids = [resource.id for resource in resources]
        if not resource_ids:
            return []
        policies = self._session.execute(
            select(MaskingPolicy).where(
                MaskingPolicy.resource_id.in_(resource_ids),
                MaskingPolicy.status == "active",
            )
        ).scalars()
        return [policy for policy in policies if self._subject_matches(policy, identity)]

    def _subject_matches(self, policy: MaskingPolicy, identity: IdentityContext) -> bool:
        """Match optional masking-policy subjects against the runtime identity."""

        if policy.subject_type is None:
            return True
        if policy.subject_type == "all":
            return True
        if policy.subject_type == "user":
            return policy.subject_id == identity.user_id
        if policy.subject_type == "role":
            return policy.subject_id in identity.roles
        return False

    def _policy_config(self, policy: MaskingPolicy) -> dict[str, object]:
        """Decode stored JSON config while protecting callers from malformed shapes."""

        loaded: Any = json.loads(policy.config_json)
        if not isinstance(loaded, dict):
            return {}
        return {str(key): value for key, value in loaded.items()}

    def _policy_output_names(
        self,
        policy: MaskingPolicy,
        projections: list[ProjectionLineage] | None,
    ) -> list[str]:
        """Resolve a source-field policy to the result columns that depend on it."""

        if projections is None:
            return [policy.field_name]
        field_name = policy.field_name.casefold()
        return list(
            dict.fromkeys(
                projection.output_name
                for projection in projections
                if projection.output_name is not None
                and field_name in {source.casefold() for source in projection.source_fields}
            )
        )

    def _row_key(self, row: dict[str, object], output_name: str) -> str | None:
        """Find a connector result key without allowing casing to bypass masking."""

        expected = output_name.casefold()
        return next((key for key in row if key.casefold() == expected), None)

    def _row_value(self, row: Mapping[str, object], output_name: str) -> object:
        """Read one result value by case-insensitive output name."""

        row_dict = dict(row)
        row_key = self._row_key(row_dict, output_name)
        return None if row_key is None else row_dict[row_key]
