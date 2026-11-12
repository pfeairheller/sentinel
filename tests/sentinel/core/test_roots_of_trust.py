# -*- coding: utf-8 -*-
"""
Unit tests for sentinel.core.roots_of_trust module
"""

import tempfile
import unittest
from pathlib import Path

import yaml

from sentinel.core.roots_of_trust import (
    AttributeRequirement,
    ChainLevel,
    EdgeRequirement,
    EdgeTarget,
    EntryPoint,
    IssuerRequirement,
    RootOfTrust,
    RootsOfTrustConfig,
    SchemaRequirement,
    ValidationOptions,
)


class TestAttributeRequirement(unittest.TestCase):
    """Test cases for AttributeRequirement class"""

    def test_from_dict_basic(self):
        """Test creating AttributeRequirement from dict"""
        data = {"path": "a.fieldName", "operator": "equals", "value": "expected"}
        req = AttributeRequirement.from_dict(data)

        self.assertEqual(req.path, "a.fieldName")
        self.assertEqual(req.operator, "equals")
        self.assertEqual(req.value, "expected")

    def test_from_dict_defaults(self):
        """Test AttributeRequirement defaults"""
        data = {}
        req = AttributeRequirement.from_dict(data)

        self.assertEqual(req.path, "")
        self.assertEqual(req.operator, "exists")
        self.assertIsNone(req.value)


class TestEdgeTarget(unittest.TestCase):
    """Test cases for EdgeTarget class"""

    def test_from_dict_parent_type(self):
        """Test EdgeTarget with parent type"""
        data = {"type": "parent"}
        target = EdgeTarget.from_dict(data)

        self.assertEqual(target.type, "parent")
        self.assertIsNone(target.schema_said)

    def test_from_dict_schema_type(self):
        """Test EdgeTarget with schema type"""
        data = {"type": "schema", "schema_said": "ESAID123"}
        target = EdgeTarget.from_dict(data)

        self.assertEqual(target.type, "schema")
        self.assertEqual(target.schema_said, "ESAID123")


class TestEdgeRequirement(unittest.TestCase):
    """Test cases for EdgeRequirement class"""

    def test_from_dict_basic(self):
        """Test creating EdgeRequirement from dict"""
        data = {
            "label": "auth",
            "target": {"type": "parent"},
            "required": True,
        }
        req = EdgeRequirement.from_dict(data)

        self.assertEqual(req.label, "auth")
        self.assertEqual(req.target.type, "parent")
        self.assertTrue(req.required)

    def test_from_dict_defaults(self):
        """Test EdgeRequirement defaults"""
        data = {}
        req = EdgeRequirement.from_dict(data)

        self.assertEqual(req.label, "")
        self.assertEqual(req.target.type, "parent")
        self.assertTrue(req.required)


class TestIssuerRequirement(unittest.TestCase):
    """Test cases for IssuerRequirement class"""

    def test_from_dict_any(self):
        """Test IssuerRequirement with 'any' wildcard"""
        data = {"aid": "any"}
        req = IssuerRequirement.from_dict(data)

        self.assertEqual(req.aid, "any")
        self.assertTrue(req.is_any())
        self.assertEqual(req.get_allowed_aids(), [])

    def test_from_dict_specific_aids(self):
        """Test IssuerRequirement with specific AIDs"""
        data = {
            "aid": ["EAID1", "EAID2"],
            "aliases": {"EAID1": "Issuer One", "EAID2": "Issuer Two"},
        }
        req = IssuerRequirement.from_dict(data)

        self.assertEqual(req.aid, ["EAID1", "EAID2"])
        self.assertFalse(req.is_any())
        self.assertEqual(req.get_allowed_aids(), ["EAID1", "EAID2"])
        self.assertEqual(req.aliases["EAID1"], "Issuer One")

    def test_from_dict_single_aid(self):
        """Test IssuerRequirement with single AID as string"""
        data = {"aid": "EAID_SINGLE"}
        req = IssuerRequirement.from_dict(data)

        self.assertFalse(req.is_any())
        self.assertEqual(req.get_allowed_aids(), ["EAID_SINGLE"])

    def test_from_dict_delegation_flags(self):
        """Test IssuerRequirement delegation flags"""
        data = {
            "aid": "any",
            "allow_delegator": True,
            "allow_delegator_chain": True,
        }
        req = IssuerRequirement.from_dict(data)

        self.assertTrue(req.allow_delegator)
        self.assertTrue(req.allow_delegator_chain)


class TestSchemaRequirement(unittest.TestCase):
    """Test cases for SchemaRequirement class"""

    def test_from_dict(self):
        """Test creating SchemaRequirement from dict"""
        data = {"said": "ESAID123", "title": "Test Schema"}
        req = SchemaRequirement.from_dict(data)

        self.assertEqual(req.said, "ESAID123")
        self.assertEqual(req.title, "Test Schema")


class TestChainLevel(unittest.TestCase):
    """Test cases for ChainLevel class"""

    def test_from_dict_basic(self):
        """Test creating ChainLevel from dict"""
        data = {
            "level": 0,
            "schema": {"said": "ESAID123", "title": "Test Schema"},
            "issuer": {"aid": "EAID123"},
        }
        level = ChainLevel.from_dict(data)

        self.assertEqual(level.level, 0)
        self.assertEqual(level.schema.said, "ESAID123")
        self.assertEqual(level.issuer.aid, "EAID123")
        self.assertEqual(level.edges, [])
        self.assertEqual(level.attributes, [])

    def test_from_dict_with_edges_and_attributes(self):
        """Test ChainLevel with edges and attributes"""
        data = {
            "level": 1,
            "schema": {"said": "ESAID456", "title": "Another Schema"},
            "issuer": {"aid": "any"},
            "edges": [{"label": "auth", "target": {"type": "parent"}}],
            "attributes": [{"path": "a.status", "operator": "equals", "value": "active"}],
        }
        level = ChainLevel.from_dict(data)

        self.assertEqual(len(level.edges), 1)
        self.assertEqual(level.edges[0].label, "auth")
        self.assertEqual(len(level.attributes), 1)
        self.assertEqual(level.attributes[0].path, "a.status")


class TestEntryPoint(unittest.TestCase):
    """Test cases for EntryPoint class"""

    def test_from_dict(self):
        """Test creating EntryPoint from dict"""
        data = {"schema_said": "ESAID_ENTRY", "title": "Entry Schema"}
        entry = EntryPoint.from_dict(data)

        self.assertEqual(entry.schema_said, "ESAID_ENTRY")
        self.assertEqual(entry.title, "Entry Schema")


class TestValidationOptions(unittest.TestCase):
    """Test cases for ValidationOptions class"""

    def test_from_dict_defaults(self):
        """Test ValidationOptions defaults"""
        data = {}
        opts = ValidationOptions.from_dict(data)

        self.assertTrue(opts.require_non_revoked)
        self.assertEqual(opts.oobi_cache_ttl, 3600)
        self.assertTrue(opts.strict_oobi_resolution)

    def test_from_dict_custom(self):
        """Test ValidationOptions with custom values"""
        data = {
            "require_non_revoked": False,
            "oobi_cache_ttl": 7200,
            "strict_oobi_resolution": False,
        }
        opts = ValidationOptions.from_dict(data)

        self.assertFalse(opts.require_non_revoked)
        self.assertEqual(opts.oobi_cache_ttl, 7200)
        self.assertFalse(opts.strict_oobi_resolution)


class TestRootOfTrust(unittest.TestCase):
    """Test cases for RootOfTrust class"""

    def test_from_dict_minimal(self):
        """Test creating RootOfTrust with minimal data"""
        data = {
            "id": "test-root",
            "title": "Test Root",
            "entry_point": {"schema_said": "ESAID_ENTRY", "title": "Entry"},
            "chain": [],
        }
        root = RootOfTrust.from_dict(data)

        self.assertEqual(root.id, "test-root")
        self.assertEqual(root.title, "Test Root")
        self.assertEqual(root.description, "")
        self.assertTrue(root.enabled)
        self.assertEqual(root.entry_point.schema_said, "ESAID_ENTRY")
        self.assertEqual(root.chain, [])

    def test_from_dict_complete(self):
        """Test creating RootOfTrust with complete data"""
        data = {
            "id": "healthcare-root",
            "title": "Healthcare Provider Chain",
            "description": "Validates healthcare providers",
            "enabled": True,
            "entry_point": {
                "schema_said": "ESAID_HEALTHCARE",
                "title": "Healthcare Provider",
            },
            "chain": [
                {
                    "level": 0,
                    "schema": {"said": "ESAID_HEALTHCARE", "title": "Healthcare Provider"},
                    "issuer": {"aid": ["EAID1", "EAID2"]},
                    "attributes": [{"path": "a.status", "operator": "equals", "value": "active"}],
                },
                {
                    "level": 1,
                    "schema": {"said": "ESAID_QVI", "title": "QVI"},
                    "issuer": {"aid": "any"},
                },
            ],
            "options": {"require_non_revoked": True},
        }
        root = RootOfTrust.from_dict(data)

        self.assertEqual(root.id, "healthcare-root")
        self.assertEqual(root.description, "Validates healthcare providers")
        self.assertEqual(len(root.chain), 2)

    def test_get_chain_level(self):
        """Test getting chain level by number"""
        data = {
            "id": "test",
            "title": "Test",
            "entry_point": {"schema_said": "E123", "title": "Entry"},
            "chain": [
                {"level": 0, "schema": {"said": "E0", "title": "Level 0"}, "issuer": {"aid": "any"}},
                {"level": 1, "schema": {"said": "E1", "title": "Level 1"}, "issuer": {"aid": "any"}},
            ],
        }
        root = RootOfTrust.from_dict(data)

        level0 = root.get_chain_level(0)
        level1 = root.get_chain_level(1)
        level2 = root.get_chain_level(2)

        self.assertIsNotNone(level0)
        self.assertEqual(level0.schema.said, "E0")
        self.assertIsNotNone(level1)
        self.assertEqual(level1.schema.said, "E1")
        self.assertIsNone(level2)


class TestRootsOfTrustConfig(unittest.TestCase):
    """Test cases for RootsOfTrustConfig class"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_load_valid_yaml(self):
        """Test loading a valid roots of trust YAML file"""
        config_file = Path(self.temp_dir) / "roots.yaml"
        config_data = {
            "roots_of_trust": [
                {
                    "id": "root-1",
                    "title": "Root One",
                    "enabled": True,
                    "entry_point": {"schema_said": "ESAID1", "title": "Schema 1"},
                    "chain": [],
                },
                {
                    "id": "root-2",
                    "title": "Root Two",
                    "enabled": True,
                    "entry_point": {"schema_said": "ESAID2", "title": "Schema 2"},
                    "chain": [],
                },
            ]
        }

        with open(config_file, "w") as f:
            yaml.safe_dump(config_data, f)

        config = RootsOfTrustConfig.load(str(config_file))

        self.assertEqual(len(config), 2)
        self.assertIsNotNone(config.get_root_by_id("root-1"))
        self.assertIsNotNone(config.get_root_by_id("root-2"))

    def test_load_empty_yaml(self):
        """Test loading an empty YAML file"""
        config_file = Path(self.temp_dir) / "empty.yaml"

        with open(config_file, "w") as f:
            f.write("")

        config = RootsOfTrustConfig.load(str(config_file))

        self.assertEqual(len(config), 0)

    def test_load_nonexistent_file(self):
        """Test loading a nonexistent file raises FileNotFoundError"""
        config_file = Path(self.temp_dir) / "nonexistent.yaml"

        with self.assertRaises(FileNotFoundError):
            RootsOfTrustConfig.load(str(config_file))

    def test_load_invalid_roots_of_trust_type(self):
        """Test loading with invalid roots_of_trust type raises ValueError"""
        config_file = Path(self.temp_dir) / "invalid.yaml"
        config_data = {"roots_of_trust": "not a list"}

        with open(config_file, "w") as f:
            yaml.safe_dump(config_data, f)

        with self.assertRaises(ValueError) as context:
            RootsOfTrustConfig.load(str(config_file))

        self.assertIn("roots_of_trust must be a list", str(context.exception))

    def test_get_roots_for_schema(self):
        """Test getting roots by entry schema SAID"""
        config_data = {
            "roots_of_trust": [
                {
                    "id": "root-a",
                    "title": "Root A",
                    "entry_point": {"schema_said": "ESAID_SHARED", "title": "Shared"},
                    "chain": [],
                },
                {
                    "id": "root-b",
                    "title": "Root B",
                    "entry_point": {"schema_said": "ESAID_SHARED", "title": "Shared"},
                    "chain": [],
                },
                {
                    "id": "root-c",
                    "title": "Root C",
                    "entry_point": {"schema_said": "ESAID_OTHER", "title": "Other"},
                    "chain": [],
                },
            ]
        }
        config = RootsOfTrustConfig.from_dict(config_data)

        shared_roots = config.get_roots_for_schema("ESAID_SHARED")
        other_roots = config.get_roots_for_schema("ESAID_OTHER")
        none_roots = config.get_roots_for_schema("ESAID_NONE")

        self.assertEqual(len(shared_roots), 2)
        self.assertEqual(len(other_roots), 1)
        self.assertEqual(len(none_roots), 0)

    def test_get_root_by_id(self):
        """Test getting a root by ID"""
        config_data = {
            "roots_of_trust": [
                {
                    "id": "unique-id",
                    "title": "Unique Root",
                    "entry_point": {"schema_said": "ESAID", "title": "Schema"},
                    "chain": [],
                }
            ]
        }
        config = RootsOfTrustConfig.from_dict(config_data)

        root = config.get_root_by_id("unique-id")
        no_root = config.get_root_by_id("nonexistent")

        self.assertIsNotNone(root)
        self.assertEqual(root.title, "Unique Root")
        self.assertIsNone(no_root)

    def test_disabled_roots_not_indexed(self):
        """Test that disabled roots are not indexed"""
        config_data = {
            "roots_of_trust": [
                {
                    "id": "enabled-root",
                    "title": "Enabled",
                    "enabled": True,
                    "entry_point": {"schema_said": "ESAID", "title": "Schema"},
                    "chain": [],
                },
                {
                    "id": "disabled-root",
                    "title": "Disabled",
                    "enabled": False,
                    "entry_point": {"schema_said": "ESAID", "title": "Schema"},
                    "chain": [],
                },
            ]
        }
        config = RootsOfTrustConfig.from_dict(config_data)

        self.assertEqual(len(config), 1)
        self.assertIsNotNone(config.get_root_by_id("enabled-root"))
        self.assertIsNone(config.get_root_by_id("disabled-root"))

    def test_get_all_roots(self):
        """Test getting all enabled roots"""
        config_data = {
            "roots_of_trust": [
                {
                    "id": "root-1",
                    "title": "Root 1",
                    "enabled": True,
                    "entry_point": {"schema_said": "ESAID1", "title": "Schema 1"},
                    "chain": [],
                },
                {
                    "id": "root-2",
                    "title": "Root 2",
                    "enabled": False,
                    "entry_point": {"schema_said": "ESAID2", "title": "Schema 2"},
                    "chain": [],
                },
            ]
        }
        config = RootsOfTrustConfig.from_dict(config_data)

        all_roots = config.get_all_roots()

        self.assertEqual(len(all_roots), 1)
        self.assertEqual(all_roots[0].id, "root-1")

    def test_iteration(self):
        """Test iterating over enabled roots"""
        config_data = {
            "roots_of_trust": [
                {
                    "id": f"root-{i}",
                    "title": f"Root {i}",
                    "entry_point": {"schema_said": f"ESAID{i}", "title": f"Schema {i}"},
                    "chain": [],
                }
                for i in range(3)
            ]
        }
        config = RootsOfTrustConfig.from_dict(config_data)

        root_ids = [root.id for root in config]

        self.assertEqual(root_ids, ["root-0", "root-1", "root-2"])


if __name__ == "__main__":
    unittest.main()
