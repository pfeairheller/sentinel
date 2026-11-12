# -*- coding: utf-8 -*-
"""
Unit tests for sentinel.core.delegation_resolver module
"""

import unittest
from unittest.mock import MagicMock

from sentinel.core.delegation_resolver import DelegationResolver


class TestDelegationResolver(unittest.TestCase):
    """Test cases for DelegationResolver class"""

    def setUp(self):
        """Set up test fixtures"""
        self.hby = MagicMock()
        self.hby.kevers = {}
        self.resolver = DelegationResolver(self.hby)

    def _create_mock_kever(self, delpre=None):
        """Helper to create a mock Kever"""
        mock_kever = MagicMock()
        mock_kever.delpre = delpre
        return mock_kever

    def test_get_immediate_delegator_non_delegated(self):
        """Test getting delegator of non-delegated AID"""
        mock_kever = self._create_mock_kever(delpre=None)
        self.hby.kevers = {"EAID1": mock_kever}

        delegator = self.resolver.get_immediate_delegator("EAID1")

        self.assertIsNone(delegator)

    def test_get_immediate_delegator_delegated(self):
        """Test getting delegator of delegated AID"""
        mock_kever = self._create_mock_kever(delpre="EDELEGATOR")
        self.hby.kevers = {"EAID1": mock_kever}

        delegator = self.resolver.get_immediate_delegator("EAID1")

        self.assertEqual(delegator, "EDELEGATOR")

    def test_get_immediate_delegator_unknown_aid(self):
        """Test getting delegator of unknown AID"""
        self.hby.kevers = {}

        delegator = self.resolver.get_immediate_delegator("EUNKNOWN")

        self.assertIsNone(delegator)

    def test_get_delegation_chain_non_delegated(self):
        """Test getting chain of non-delegated AID"""
        mock_kever = self._create_mock_kever(delpre=None)
        self.hby.kevers = {"EAID1": mock_kever}

        chain = self.resolver.get_delegation_chain("EAID1")

        self.assertEqual(chain, ["EAID1"])

    def test_get_delegation_chain_single_delegation(self):
        """Test getting chain with single delegation level"""
        mock_delegated = self._create_mock_kever(delpre="EDELEGATOR")
        mock_delegator = self._create_mock_kever(delpre=None)
        self.hby.kevers = {
            "EDELEGATED": mock_delegated,
            "EDELEGATOR": mock_delegator,
        }

        chain = self.resolver.get_delegation_chain("EDELEGATED")

        self.assertEqual(chain, ["EDELEGATED", "EDELEGATOR"])

    def test_get_delegation_chain_multiple_levels(self):
        """Test getting chain with multiple delegation levels"""
        mock_leaf = self._create_mock_kever(delpre="EMIDDLE")
        mock_middle = self._create_mock_kever(delpre="EROOT")
        mock_root = self._create_mock_kever(delpre=None)
        self.hby.kevers = {
            "ELEAF": mock_leaf,
            "EMIDDLE": mock_middle,
            "EROOT": mock_root,
        }

        chain = self.resolver.get_delegation_chain("ELEAF")

        self.assertEqual(chain, ["ELEAF", "EMIDDLE", "EROOT"])

    def test_get_delegation_chain_circular_prevention(self):
        """Test that circular delegation is detected and handled"""
        mock_a = self._create_mock_kever(delpre="EB")
        mock_b = self._create_mock_kever(delpre="EA")  # Circular back to A
        self.hby.kevers = {
            "EA": mock_a,
            "EB": mock_b,
        }

        chain = self.resolver.get_delegation_chain("EA")

        # Should stop when circular reference is detected
        self.assertEqual(chain, ["EA", "EB"])

    def test_is_delegated_by_direct(self):
        """Test is_delegated_by with direct delegation"""
        mock_delegated = self._create_mock_kever(delpre="EDELEGATOR")
        self.hby.kevers = {"EDELEGATED": mock_delegated}

        result = self.resolver.is_delegated_by(
            "EDELEGATED", "EDELEGATOR", transitive=False
        )

        self.assertTrue(result)

    def test_is_delegated_by_direct_negative(self):
        """Test is_delegated_by with different delegator"""
        mock_delegated = self._create_mock_kever(delpre="EOTHER")
        self.hby.kevers = {"EDELEGATED": mock_delegated}

        result = self.resolver.is_delegated_by(
            "EDELEGATED", "EDELEGATOR", transitive=False
        )

        self.assertFalse(result)

    def test_is_delegated_by_transitive(self):
        """Test is_delegated_by with transitive delegation"""
        mock_leaf = self._create_mock_kever(delpre="EMIDDLE")
        mock_middle = self._create_mock_kever(delpre="EROOT")
        mock_root = self._create_mock_kever(delpre=None)
        self.hby.kevers = {
            "ELEAF": mock_leaf,
            "EMIDDLE": mock_middle,
            "EROOT": mock_root,
        }

        result = self.resolver.is_delegated_by("ELEAF", "EROOT", transitive=True)

        self.assertTrue(result)

    def test_is_delegated_by_transitive_not_in_chain(self):
        """Test is_delegated_by transitive with AID not in chain"""
        mock_leaf = self._create_mock_kever(delpre="EMIDDLE")
        mock_middle = self._create_mock_kever(delpre="EROOT")
        mock_root = self._create_mock_kever(delpre=None)
        self.hby.kevers = {
            "ELEAF": mock_leaf,
            "EMIDDLE": mock_middle,
            "EROOT": mock_root,
        }

        result = self.resolver.is_delegated_by("ELEAF", "EOTHER", transitive=True)

        self.assertFalse(result)

    def test_is_delegated_by_same_aid(self):
        """Test is_delegated_by with same AID returns True"""
        mock_kever = self._create_mock_kever(delpre=None)
        self.hby.kevers = {"EAID": mock_kever}

        result = self.resolver.is_delegated_by("EAID", "EAID", transitive=False)

        self.assertTrue(result)

    def test_is_delegated(self):
        """Test is_delegated for delegated AID"""
        mock_kever = self._create_mock_kever(delpre="EDELEGATOR")
        self.hby.kevers = {"EAID": mock_kever}

        result = self.resolver.is_delegated("EAID")

        self.assertTrue(result)

    def test_is_not_delegated(self):
        """Test is_delegated for non-delegated AID"""
        mock_kever = self._create_mock_kever(delpre=None)
        self.hby.kevers = {"EAID": mock_kever}

        result = self.resolver.is_delegated("EAID")

        self.assertFalse(result)

    def test_get_root_delegator_non_delegated(self):
        """Test get_root_delegator for non-delegated AID"""
        mock_kever = self._create_mock_kever(delpre=None)
        self.hby.kevers = {"EAID": mock_kever}

        root = self.resolver.get_root_delegator("EAID")

        self.assertEqual(root, "EAID")

    def test_get_root_delegator_delegated(self):
        """Test get_root_delegator for delegated AID"""
        mock_leaf = self._create_mock_kever(delpre="EMIDDLE")
        mock_middle = self._create_mock_kever(delpre="EROOT")
        mock_root = self._create_mock_kever(delpre=None)
        self.hby.kevers = {
            "ELEAF": mock_leaf,
            "EMIDDLE": mock_middle,
            "EROOT": mock_root,
        }

        root = self.resolver.get_root_delegator("ELEAF")

        self.assertEqual(root, "EROOT")


if __name__ == "__main__":
    unittest.main()
