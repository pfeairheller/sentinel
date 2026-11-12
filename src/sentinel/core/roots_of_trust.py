# -*- encoding: utf-8 -*-
"""
sentinel.core.roots_of_trust module

Configuration classes for defining "Roots of Trust" that Sentinel (acting as a Verifier)
will accept for credential chain validation.

"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml


@dataclass
class AttributeRequirement:
    """Requirement for validating a credential attribute."""

    path: str
    operator: str
    value: Optional[Any] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AttributeRequirement":
        """Create an AttributeRequirement from a dictionary."""
        return cls(
            path=data.get("path", ""),
            operator=data.get("operator", "exists"),
            value=data.get("value"),
        )


@dataclass
class EdgeTarget:
    """Target specification for an edge requirement."""

    type: str  # "parent" or "schema"
    schema_said: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EdgeTarget":
        """Create an EdgeTarget from a dictionary."""
        return cls(
            type=data.get("type", "parent"),
            schema_said=data.get("schema_said"),
        )


@dataclass
class EdgeRequirement:
    """Requirement for validating a credential edge."""

    label: str
    target: EdgeTarget
    required: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EdgeRequirement":
        """Create an EdgeRequirement from a dictionary."""
        target_data = data.get("target", {})
        return cls(
            label=data.get("label", ""),
            target=EdgeTarget.from_dict(target_data),
            required=data.get("required", True),
        )


@dataclass
class IssuerRequirement:
    """Requirement for validating a credential issuer."""

    aid: Union[str, List[str]]  # "any" for wildcard, or list of specific AIDs
    aliases: Dict[str, str] = field(default_factory=dict)
    allow_delegator: bool = False
    allow_delegator_chain: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IssuerRequirement":
        """Create an IssuerRequirement from a dictionary."""
        return cls(
            aid=data.get("aid", "any"),
            aliases=data.get("aliases", {}),
            allow_delegator=data.get("allow_delegator", False),
            allow_delegator_chain=data.get("allow_delegator_chain", False),
        )

    def is_any(self) -> bool:
        """Check if the issuer requirement allows any AID."""
        return self.aid == "any"

    def get_allowed_aids(self) -> List[str]:
        """Get the list of allowed AIDs."""
        if self.is_any():
            return []
        if isinstance(self.aid, str):
            return [self.aid]
        return self.aid


@dataclass
class SchemaRequirement:
    """Requirement for validating a credential schema."""

    said: str
    title: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SchemaRequirement":
        """Create a SchemaRequirement from a dictionary."""
        return cls(
            said=data.get("said", ""),
            title=data.get("title", ""),
        )


@dataclass
class ChainLevel:
    """A level in the credential chain (from leaf to root)."""

    level: int
    schema: SchemaRequirement
    issuer: IssuerRequirement
    edges: List[EdgeRequirement] = field(default_factory=list)
    attributes: List[AttributeRequirement] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChainLevel":
        """Create a ChainLevel from a dictionary."""
        schema_data = data.get("schema", {})
        issuer_data = data.get("issuer", {})
        edges_data = data.get("edges", [])
        attributes_data = data.get("attributes", [])

        return cls(
            level=data.get("level", 0),
            schema=SchemaRequirement.from_dict(schema_data),
            issuer=IssuerRequirement.from_dict(issuer_data),
            edges=[EdgeRequirement.from_dict(e) for e in edges_data],
            attributes=[AttributeRequirement.from_dict(a) for a in attributes_data],
        )


@dataclass
class EntryPoint:
    """Entry point schema definition for a root of trust."""

    schema_said: str
    title: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EntryPoint":
        """Create an EntryPoint from a dictionary."""
        return cls(
            schema_said=data.get("schema_said", ""),
            title=data.get("title", ""),
        )


@dataclass
class ValidationOptions:
    """Validation options for a root of trust."""

    require_non_revoked: bool = True
    oobi_cache_ttl: int = 3600
    strict_oobi_resolution: bool = True

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationOptions":
        """Create ValidationOptions from a dictionary."""
        return cls(
            require_non_revoked=data.get("require_non_revoked", True),
            oobi_cache_ttl=data.get("oobi_cache_ttl", 3600),
            strict_oobi_resolution=data.get("strict_oobi_resolution", True),
        )


@dataclass
class RootOfTrust:
    """A complete root of trust specification."""

    id: str
    title: str
    entry_point: EntryPoint
    chain: List[ChainLevel]
    description: str = ""
    enabled: bool = True
    options: ValidationOptions = field(default_factory=ValidationOptions)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RootOfTrust":
        """Create a RootOfTrust from a dictionary."""
        entry_point_data = data.get("entry_point", {})
        chain_data = data.get("chain", [])
        options_data = data.get("options", {})

        return cls(
            id=data.get("id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
            entry_point=EntryPoint.from_dict(entry_point_data),
            chain=[ChainLevel.from_dict(c) for c in chain_data],
            options=ValidationOptions.from_dict(options_data),
        )

    def get_chain_level(self, level: int) -> Optional[ChainLevel]:
        """Get the chain level by level number."""
        for chain_level in self.chain:
            if chain_level.level == level:
                return chain_level
        return None


class RootsOfTrustConfig:
    """
    Configuration loader and accessor for Roots of Trust specifications.

    This class reads a YAML configuration file containing root of trust definitions
    and provides methods to query and access them.

    Example:
        config = RootsOfTrustConfig.load("/path/to/roots-of-trust.yaml")
        roots = config.get_roots_for_schema("ESAID...")
        root = config.get_root_by_id("healthcare-provider-chain")
    """

    def __init__(self, roots: Optional[List[RootOfTrust]] = None):
        """Initialize with a list of root of trust definitions."""
        self._roots = roots or []
        self._by_id: Dict[str, RootOfTrust] = {}
        self._by_schema: Dict[str, List[RootOfTrust]] = {}
        self._index_roots()

    def _index_roots(self) -> None:
        """Build indexes for fast lookup."""
        self._by_id = {}
        self._by_schema = {}

        for root in self._roots:
            if not root.enabled:
                continue

            self._by_id[root.id] = root

            schema_said = root.entry_point.schema_said
            if schema_said not in self._by_schema:
                self._by_schema[schema_said] = []
            self._by_schema[schema_said].append(root)

    @classmethod
    def load(cls, config_path: str) -> "RootsOfTrustConfig":
        """
        Load roots of trust configuration from a YAML file.

        Args:
            config_path: Path to the YAML configuration file

        Returns:
            RootsOfTrustConfig instance with loaded configuration

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            yaml.YAMLError: If the YAML is malformed
            ValueError: If the configuration is invalid
        """
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Roots of trust config file not found: {config_path}")

        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if data is None:
            return cls([])

        roots_data = data.get("roots_of_trust", [])
        if not isinstance(roots_data, list):
            raise ValueError("roots_of_trust must be a list")

        roots = [RootOfTrust.from_dict(r) for r in roots_data]
        return cls(roots)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RootsOfTrustConfig":
        """
        Create a RootsOfTrustConfig from a dictionary.

        Args:
            data: Dictionary containing roots_of_trust configuration

        Returns:
            RootsOfTrustConfig instance
        """
        roots_data = data.get("roots_of_trust", [])
        if not isinstance(roots_data, list):
            roots_data = []

        roots = [RootOfTrust.from_dict(r) for r in roots_data]
        return cls(roots)

    def get_roots_for_schema(self, schema_said: str) -> List[RootOfTrust]:
        """
        Get all enabled roots of trust that accept credentials with the given schema.

        Args:
            schema_said: The SAID of the entry point schema

        Returns:
            List of matching RootOfTrust instances
        """
        return self._by_schema.get(schema_said, [])

    def get_root_by_id(self, root_id: str) -> Optional[RootOfTrust]:
        """
        Get a specific root of trust by its ID.

        Args:
            root_id: The unique identifier of the root

        Returns:
            The RootOfTrust if found, None otherwise
        """
        return self._by_id.get(root_id)

    def get_all_roots(self) -> List[RootOfTrust]:
        """Get all enabled roots of trust."""
        return [r for r in self._roots if r.enabled]

    def __len__(self) -> int:
        """Return the number of enabled roots."""
        return len(self._by_id)

    def __iter__(self):
        """Iterate over enabled roots."""
        return iter(self.get_all_roots())
