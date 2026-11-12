# -*- coding: utf-8 -*-
"""
Unit tests for sentinel.core.chain_validator module
"""

import unittest
from unittest.mock import MagicMock, patch

from sentinel.core.chain_validator import ChainValidator, ValidationError, ValidationResult
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


class TestValidationResult(unittest.TestCase):
    """Test cases for ValidationResult class"""

    def test_initial_state(self):
        """Test ValidationResult initial state"""
        result = ValidationResult(
            root_id="test-root",
            root_title="Test Root",
            valid=True,
        )

        self.assertEqual(result.root_id, "test-root")
        self.assertEqual(result.root_title, "Test Root")
        self.assertTrue(result.valid)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.chain_validated, [])

    def test_add_error(self):
        """Test adding an error invalidates the result"""
        result = ValidationResult(
            root_id="test-root",
            root_title="Test Root",
            valid=True,
        )

        result.add_error(
            level=0,
            credential_said="ESAID123",
            message="Test error",
            field="issuer",
        )

        self.assertFalse(result.valid)
        self.assertEqual(len(result.errors), 1)
        self.assertEqual(result.errors[0].level, 0)
        self.assertEqual(result.errors[0].credential_said, "ESAID123")
        self.assertEqual(result.errors[0].message, "Test error")
        self.assertEqual(result.errors[0].field, "issuer")


class TestChainValidator(unittest.TestCase):
    """Test cases for ChainValidator class"""

    def setUp(self):
        """Set up test fixtures with mocked KERI components"""
        self.hby = MagicMock()
        self.rgy = MagicMock()

        # Set up kevers dictionary
        self.hby.kevers = {}

        # Create a simple roots config
        self.roots_config = RootsOfTrustConfig.from_dict({
            "roots_of_trust": [
                {
                    "id": "test-root",
                    "title": "Test Root",
                    "entry_point": {
                        "schema_said": "ESCHEMA_ENTRY",
                        "title": "Entry Schema",
                    },
                    "chain": [
                        {
                            "level": 0,
                            "schema": {"said": "ESCHEMA_ENTRY", "title": "Entry"},
                            "issuer": {"aid": ["EISSUER_ALLOWED"]},
                            "attributes": [
                                {"path": "a.status", "operator": "equals", "value": "active"}
                            ],
                        }
                    ],
                    "options": {"require_non_revoked": True},
                }
            ]
        })

        self.validator = ChainValidator(self.hby, self.rgy, self.roots_config)

    def _create_mock_credential(self, said, schema, issuer, attrib=None, edge=None, regi="EREG"):
        """Helper to create a mock credential"""
        mock_creder = MagicMock()
        mock_creder.said = said
        mock_creder.schema = schema
        mock_creder.issuer = issuer
        mock_creder.attrib = attrib or {}
        mock_creder.edge = edge or {}
        mock_creder.regi = regi
        return mock_creder

    def test_validate_credential_not_found(self):
        """Test validation with non-existent credential"""
        self.rgy.reger.cloneCred.return_value = (None, None, None, None)

        results = self.validator.validate_credential("ESAID_NONEXISTENT")

        self.assertEqual(results, [])

    def test_validate_credential_no_matching_roots(self):
        """Test validation with no matching roots of trust"""
        mock_creder = self._create_mock_credential(
            said="ESAID123",
            schema="ESCHEMA_UNKNOWN",
            issuer="EISSUER1",
        )
        self.rgy.reger.cloneCred.return_value = (mock_creder, None, None, None)

        results = self.validator.validate_credential("ESAID123")

        self.assertEqual(results, [])

    def test_validate_credential_success(self):
        """Test successful credential validation"""
        mock_creder = self._create_mock_credential(
            said="ESAID123",
            schema="ESCHEMA_ENTRY",
            issuer="EISSUER_ALLOWED",
            attrib={"a": {"status": "active"}},
        )
        self.rgy.reger.cloneCred.return_value = (mock_creder, None, None, None)

        # Mock registry for revocation check
        mock_tever = MagicMock()
        mock_status = MagicMock()
        mock_status.et = "iss"  # Not revoked
        mock_tever.vcState.return_value = mock_status
        self.rgy.reger.tevers = {"EREG": mock_tever}

        results = self.validator.validate_credential("ESAID123")

        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].valid)
        self.assertEqual(results[0].root_id, "test-root")

    def test_validate_credential_wrong_issuer(self):
        """Test validation fails with wrong issuer"""
        mock_creder = self._create_mock_credential(
            said="ESAID123",
            schema="ESCHEMA_ENTRY",
            issuer="EISSUER_WRONG",
            attrib={"a": {"status": "active"}},
        )
        self.rgy.reger.cloneCred.return_value = (mock_creder, None, None, None)

        # Mock registry for revocation check
        mock_tever = MagicMock()
        mock_status = MagicMock()
        mock_status.et = "iss"
        mock_tever.vcState.return_value = mock_status
        self.rgy.reger.tevers = {"EREG": mock_tever}

        results = self.validator.validate_credential("ESAID123")

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].valid)
        self.assertTrue(any("issuer" in e.field for e in results[0].errors if e.field))

    def test_validate_credential_wrong_attribute(self):
        """Test validation fails with wrong attribute value"""
        mock_creder = self._create_mock_credential(
            said="ESAID123",
            schema="ESCHEMA_ENTRY",
            issuer="EISSUER_ALLOWED",
            attrib={"a": {"status": "inactive"}},
        )
        self.rgy.reger.cloneCred.return_value = (mock_creder, None, None, None)

        # Mock registry for revocation check
        mock_tever = MagicMock()
        mock_status = MagicMock()
        mock_status.et = "iss"
        mock_tever.vcState.return_value = mock_status
        self.rgy.reger.tevers = {"EREG": mock_tever}

        results = self.validator.validate_credential("ESAID123")

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].valid)
        self.assertTrue(any("attributes" in e.field for e in results[0].errors if e.field))

    def test_validate_credential_schema_mismatch(self):
        """Test validation fails with schema mismatch at chain level"""
        # Create a root that expects a different schema at level 0
        roots_config = RootsOfTrustConfig.from_dict({
            "roots_of_trust": [
                {
                    "id": "schema-test",
                    "title": "Schema Test",
                    "entry_point": {"schema_said": "ESCHEMA_ENTRY", "title": "Entry"},
                    "chain": [
                        {
                            "level": 0,
                            "schema": {"said": "ESCHEMA_DIFFERENT", "title": "Different"},
                            "issuer": {"aid": "any"},
                        }
                    ],
                }
            ]
        })
        validator = ChainValidator(self.hby, self.rgy, roots_config)

        mock_creder = self._create_mock_credential(
            said="ESAID123",
            schema="ESCHEMA_ENTRY",
            issuer="EISSUER1",
        )
        self.rgy.reger.cloneCred.return_value = (mock_creder, None, None, None)
        self.rgy.reger.tevers = {}

        results = validator.validate_credential("ESAID123")

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].valid)
        self.assertTrue(any("schema" in e.field for e in results[0].errors if e.field))

    def test_validate_issuer_any(self):
        """Test issuer validation with 'any' requirement"""
        requirement = IssuerRequirement(aid="any")

        valid, error = self.validator._validate_issuer("EANY_ISSUER", requirement)

        self.assertTrue(valid)
        self.assertEqual(error, "")

    def test_validate_issuer_direct_match(self):
        """Test issuer validation with direct AID match"""
        requirement = IssuerRequirement(aid=["EISSUER1", "EISSUER2"])

        valid, error = self.validator._validate_issuer("EISSUER1", requirement)

        self.assertTrue(valid)

    def test_validate_issuer_with_delegation(self):
        """Test issuer validation with delegation allowed"""
        requirement = IssuerRequirement(
            aid=["EDELEGATOR"],
            allow_delegator=True,
        )

        # Mock the delegation resolver
        self.validator.delegation_resolver.get_immediate_delegator = MagicMock(
            return_value="EDELEGATOR"
        )

        valid, error = self.validator._validate_issuer("EDELEGATED", requirement)

        self.assertTrue(valid)

    def test_validate_issuer_with_transitive_delegation(self):
        """Test issuer validation with transitive delegation"""
        requirement = IssuerRequirement(
            aid=["EROOT"],
            allow_delegator_chain=True,
        )

        # Mock the delegation resolver
        self.validator.delegation_resolver.get_delegation_chain = MagicMock(
            return_value=["EDELEGATED", "EMIDDLE", "EROOT"]
        )

        valid, error = self.validator._validate_issuer("EDELEGATED", requirement)

        self.assertTrue(valid)

    def test_is_revoked_check(self):
        """Test revocation status check"""
        mock_creder = self._create_mock_credential(
            said="ESAID123",
            schema="ESCHEMA",
            issuer="EISSUER",
            regi="EREG123",
        )

        # Mock revoked status
        mock_tever = MagicMock()
        mock_status = MagicMock()
        mock_status.et = "rev"  # Revoked
        mock_tever.vcState.return_value = mock_status
        self.rgy.reger.tevers = {"EREG123": mock_tever}

        is_revoked = self.validator._is_revoked(mock_creder)

        self.assertTrue(is_revoked)

    def test_is_not_revoked(self):
        """Test non-revoked credential"""
        mock_creder = self._create_mock_credential(
            said="ESAID123",
            schema="ESCHEMA",
            issuer="EISSUER",
            regi="EREG123",
        )

        # Mock issued (not revoked) status
        mock_tever = MagicMock()
        mock_status = MagicMock()
        mock_status.et = "iss"  # Issued, not revoked
        mock_tever.vcState.return_value = mock_status
        self.rgy.reger.tevers = {"EREG123": mock_tever}

        is_revoked = self.validator._is_revoked(mock_creder)

        self.assertFalse(is_revoked)

    def test_build_credential_chain_single(self):
        """Test building chain with single credential (no edges)"""
        mock_creder = self._create_mock_credential(
            said="ESAID1",
            schema="ESCHEMA",
            issuer="EISSUER",
            edge={},
        )

        chain = self.validator._build_credential_chain(mock_creder)

        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0].said, "ESAID1")

    def test_build_credential_chain_multiple(self):
        """Test building chain with multiple credentials"""
        mock_parent = self._create_mock_credential(
            said="ESAID_PARENT",
            schema="ESCHEMA_PARENT",
            issuer="EISSUER_PARENT",
            edge={},
        )
        mock_child = self._create_mock_credential(
            said="ESAID_CHILD",
            schema="ESCHEMA_CHILD",
            issuer="EISSUER_CHILD",
            edge={"auth": {"n": "ESAID_PARENT"}},
        )

        # Configure cloneCred to return different credentials based on SAID
        def clone_cred_side_effect(said):
            if said == "ESAID_PARENT":
                return (mock_parent, None, None, None)
            return (None, None, None, None)

        self.rgy.reger.cloneCred.side_effect = clone_cred_side_effect

        chain = self.validator._build_credential_chain(mock_child)

        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[0].said, "ESAID_CHILD")
        self.assertEqual(chain[1].said, "ESAID_PARENT")

    def test_get_validation_summary(self):
        """Test getting validation summary"""
        results = [
            ValidationResult(root_id="root1", root_title="Root 1", valid=True, chain_validated=["A", "B"]),
            ValidationResult(root_id="root2", root_title="Root 2", valid=False, chain_validated=["A"]),
        ]
        results[1].add_error(0, "ESAID", "Test error")

        summary = self.validator.get_validation_summary(results)

        self.assertEqual(summary["total_roots_checked"], 2)
        self.assertEqual(summary["valid_count"], 1)
        self.assertEqual(summary["invalid_count"], 1)
        self.assertEqual(len(summary["results"]), 2)

    def test_validate_edges_required_missing(self):
        """Test edge validation with missing required edge"""
        mock_creder = self._create_mock_credential(
            said="ESAID",
            schema="ESCHEMA",
            issuer="EISSUER",
            edge={},  # No edges
        )

        level_spec = ChainLevel(
            level=0,
            schema=SchemaRequirement(said="ESCHEMA", title="Schema"),
            issuer=IssuerRequirement(aid="any"),
            edges=[
                EdgeRequirement(
                    label="auth",
                    target=EdgeTarget(type="parent"),
                    required=True,
                )
            ],
        )

        errors = self.validator._validate_edges(mock_creder, level_spec, [mock_creder])

        self.assertEqual(len(errors), 1)
        self.assertIn("Required edge 'auth' not found", errors[0])

    def test_validate_edges_optional_missing(self):
        """Test edge validation with missing optional edge (no error)"""
        mock_creder = self._create_mock_credential(
            said="ESAID",
            schema="ESCHEMA",
            issuer="EISSUER",
            edge={},
        )

        level_spec = ChainLevel(
            level=0,
            schema=SchemaRequirement(said="ESCHEMA", title="Schema"),
            issuer=IssuerRequirement(aid="any"),
            edges=[
                EdgeRequirement(
                    label="optional_edge",
                    target=EdgeTarget(type="parent"),
                    required=False,
                )
            ],
        )

        errors = self.validator._validate_edges(mock_creder, level_spec, [mock_creder])

        self.assertEqual(len(errors), 0)


if __name__ == "__main__":
    unittest.main()
