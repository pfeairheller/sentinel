# -*- encoding: utf-8 -*-
"""
sentinel.core.chain_validator module

Validates credentials against roots of trust specifications.

"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from keri import help
from keri.kering import Ilks

from sentinel.core.attribute_matcher import AttributeMatcher
from sentinel.core.delegation_resolver import DelegationResolver
from sentinel.core.roots_of_trust import (
    ChainLevel,
    IssuerRequirement,
    RootOfTrust,
    RootsOfTrustConfig,
)

logger = help.ogler.getLogger()


@dataclass
class ValidationError:
    """A validation error with context."""

    level: int
    credential_said: str
    message: str
    field: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of validating a credential against a root of trust."""

    root_id: str
    root_title: str
    valid: bool
    errors: List[ValidationError] = field(default_factory=list)
    chain_validated: List[str] = field(default_factory=list)

    def add_error(
        self,
        level: int,
        credential_said: str,
        message: str,
        field: Optional[str] = None,
    ) -> None:
        """Add a validation error."""
        self.errors.append(
            ValidationError(
                level=level,
                credential_said=credential_said,
                message=message,
                field=field,
            )
        )
        self.valid = False


class ChainValidator:
    """
    Validates credentials against roots of trust specifications.

    This class walks the credential chain and validates each level against
    the corresponding requirements in the root of trust specification.

    Example:
        validator = ChainValidator(hby, rgy, roots_config)
        results = validator.validate_credential(credential_said)
        for result in results:
            if result.valid:
                print(f"Valid against root: {result.root_id}")
    """

    def __init__(self, hby, rgy, roots_config: RootsOfTrustConfig):
        """
        Initialize the ChainValidator.

        Args:
            hby: The Habery instance
            rgy: The Regery instance for credential access
            roots_config: The roots of trust configuration
        """
        self.hby = hby
        self.rgy = rgy
        self.roots_config = roots_config
        self.delegation_resolver = DelegationResolver(hby)
        self.attribute_matcher = AttributeMatcher()

    def validate_credential(self, said: str) -> List[ValidationResult]:
        """
        Validate a credential against all applicable roots of trust.

        Args:
            said: The SAID of the credential to validate

        Returns:
            List of ValidationResult objects, one for each applicable root
        """
        results = []

        # Load the credential
        creder, prefixer, seqner, saider = self.rgy.reger.cloneCred(said=said)
        if not creder:
            logger.error(f"ChainValidator: Credential {said} not found")
            return results

        # Find applicable roots by schema
        schema_said = creder.schema
        roots = self.roots_config.get_roots_for_schema(schema_said)

        if not roots:
            logger.info(
                f"ChainValidator: No roots of trust found for schema {schema_said}"
            )
            return results

        # Validate against each applicable root
        for root in roots:
            result = self._validate_against_root(creder, root)
            results.append(result)

        return results

    def validate_credential_chain(
        self, said: str, root_id: Optional[str] = None
    ) -> Optional[ValidationResult]:
        """
        Validate a credential chain against a specific root of trust.

        Args:
            said: The SAID of the entry credential
            root_id: Optional specific root ID to validate against

        Returns:
            ValidationResult if a matching root is found, None otherwise
        """
        creder, prefixer, seqner, saider = self.rgy.reger.cloneCred(said=said)
        if not creder:
            return None

        if root_id:
            root = self.roots_config.get_root_by_id(root_id)
            if root and root.entry_point.schema_said == creder.schema:
                return self._validate_against_root(creder, root)
            return None

        # Find the first matching root
        roots = self.roots_config.get_roots_for_schema(creder.schema)
        for root in roots:
            result = self._validate_against_root(creder, root)
            if result.valid:
                return result

        # Return the first failure if none passed
        return roots[0] if roots else None

    def _validate_against_root(self, creder, root: RootOfTrust) -> ValidationResult:
        """
        Validate a credential against a specific root of trust.

        Args:
            creder: The credential to validate
            root: The root of trust specification

        Returns:
            ValidationResult indicating success or failure with errors
        """
        result = ValidationResult(
            root_id=root.id,
            root_title=root.title,
            valid=True,
        )

        # Build the credential chain
        chain = self._build_credential_chain(creder)

        # Validate each level
        for level_spec in root.chain:
            level_num = level_spec.level
            if level_num >= len(chain):
                result.add_error(
                    level=level_num,
                    credential_said="",
                    message=f"Chain too short: expected level {level_num}, chain length is {len(chain)}",
                )
                continue

            level_creder = chain[level_num]
            result.chain_validated.append(level_creder.said)

            # Validate schema
            if level_creder.schema != level_spec.schema.said:
                result.add_error(
                    level=level_num,
                    credential_said=level_creder.said,
                    message=f"Schema mismatch: expected {level_spec.schema.said}, got {level_creder.schema}",
                    field="schema",
                )

            # Validate issuer
            issuer_valid, issuer_error = self._validate_issuer(
                level_creder.issuer, level_spec.issuer
            )
            if not issuer_valid:
                result.add_error(
                    level=level_num,
                    credential_said=level_creder.said,
                    message=issuer_error,
                    field="issuer",
                )

            # Validate edges
            edge_errors = self._validate_edges(level_creder, level_spec, chain)
            for error in edge_errors:
                result.add_error(
                    level=level_num,
                    credential_said=level_creder.said,
                    message=error,
                    field="edges",
                )

            # Validate attributes
            if level_spec.attributes:
                attrib = level_creder.attrib or {}
                attr_errors = self.attribute_matcher.validate_all(
                    attrib, level_spec.attributes
                )
                for error in attr_errors:
                    result.add_error(
                        level=level_num,
                        credential_said=level_creder.said,
                        message=error,
                        field="attributes",
                    )

            # Validate revocation status if required
            if root.options.require_non_revoked:
                if self._is_revoked(level_creder):
                    result.add_error(
                        level=level_num,
                        credential_said=level_creder.said,
                        message="Credential has been revoked",
                        field="status",
                    )

        return result

    def _build_credential_chain(self, creder) -> List:
        """
        Build the credential chain from leaf to root.

        Args:
            creder: The leaf credential

        Returns:
            List of credentials from leaf (index 0) to root (index N)
        """
        chain = [creder]
        current = creder

        while True:
            edges = current.edge or {}
            parent_said = None

            # Look for edges pointing to parent credentials
            for key, value in edges.items():
                if key == "d":
                    continue

                if isinstance(value, dict) and "n" in value:
                    parent_said = value["n"]
                    break

            if not parent_said:
                break

            parent_creder, *_ = self.rgy.reger.cloneCred(said=parent_said)
            if not parent_creder:
                logger.warning(
                    f"ChainValidator: Parent credential {parent_said} not found in registry"
                )
                break

            chain.append(parent_creder)
            current = parent_creder

        return chain

    def _validate_issuer(
        self, issuer_aid: str, requirement: IssuerRequirement
    ) -> Tuple[bool, str]:
        """
        Validate an issuer AID against issuer requirements.

        Args:
            issuer_aid: The AID of the credential issuer
            requirement: The issuer requirement specification

        Returns:
            Tuple of (is_valid, error_message)
        """
        # "any" allows any issuer
        if requirement.is_any():
            return True, ""

        allowed_aids = requirement.get_allowed_aids()

        # Direct match
        if issuer_aid in allowed_aids:
            return True, ""

        # Check delegation if allowed
        if requirement.allow_delegator:
            immediate_delegator = self.delegation_resolver.get_immediate_delegator(
                issuer_aid
            )
            if immediate_delegator and immediate_delegator in allowed_aids:
                return True, ""

        if requirement.allow_delegator_chain:
            chain = self.delegation_resolver.get_delegation_chain(issuer_aid)
            for delegator in chain[1:]:  # Skip the issuer itself
                if delegator in allowed_aids:
                    return True, ""

        # Build error message with alias if available
        allowed_str = ", ".join(
            f"{aid} ({requirement.aliases.get(aid, 'unknown')})"
            for aid in allowed_aids
        )
        return False, f"Issuer {issuer_aid} not in allowed list: [{allowed_str}]"

    def _validate_edges(
        self, creder, level_spec: ChainLevel, chain: List
    ) -> List[str]:
        """
        Validate credential edges against edge requirements.

        Args:
            creder: The credential to validate
            level_spec: The chain level specification
            chain: The full credential chain

        Returns:
            List of error messages (empty if all valid)
        """
        errors = []
        edges = creder.edge or {}

        for edge_req in level_spec.edges:
            label = edge_req.label

            # Check if edge exists
            edge_value = edges.get(label)
            if edge_value is None:
                if edge_req.required:
                    errors.append(f"Required edge '{label}' not found")
                continue

            # Validate edge target
            if edge_req.target.type == "schema" and edge_req.target.schema_said:
                if isinstance(edge_value, dict) and "n" in edge_value:
                    target_said = edge_value["n"]
                    target_creder, *_ = self.rgy.reger.cloneCred(said=target_said)
                    if target_creder:
                        if target_creder.schema != edge_req.target.schema_said:
                            errors.append(
                                f"Edge '{label}' points to wrong schema: "
                                f"expected {edge_req.target.schema_said}, "
                                f"got {target_creder.schema}"
                            )
                    else:
                        errors.append(
                            f"Edge '{label}' target credential {target_said} not found"
                        )

        return errors

    def _is_revoked(self, creder) -> bool:
        """
        Check if a credential has been revoked.

        Args:
            creder: The credential to check

        Returns:
            True if revoked, False otherwise
        """
        try:
            registry_said = creder.regi
            if registry_said not in self.rgy.reger.tevers:
                return False

            tever = self.rgy.reger.tevers[registry_said]
            status = tever.vcState(creder.said)

            # Check if the status indicates revocation
            return status.et in [Ilks.rev, Ilks.brv]
        except Exception as e:
            logger.warning(f"ChainValidator: Error checking revocation status: {e}")
            return False

    def get_validation_summary(
        self, results: List[ValidationResult]
    ) -> Dict[str, Any]:
        """
        Get a summary of validation results.

        Args:
            results: List of validation results

        Returns:
            Summary dictionary with counts and details
        """
        return {
            "total_roots_checked": len(results),
            "valid_count": sum(1 for r in results if r.valid),
            "invalid_count": sum(1 for r in results if not r.valid),
            "results": [
                {
                    "root_id": r.root_id,
                    "root_title": r.root_title,
                    "valid": r.valid,
                    "error_count": len(r.errors),
                    "chain_length": len(r.chain_validated),
                }
                for r in results
            ],
        }
