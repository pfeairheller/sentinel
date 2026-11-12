# -*- coding: utf-8 -*-
"""
Unit tests for sentinel.core.attribute_matcher module
"""

import unittest
from datetime import date, datetime

from sentinel.core.attribute_matcher import AttributeMatcher
from sentinel.core.roots_of_trust import AttributeRequirement


class TestAttributeMatcher(unittest.TestCase):
    """Test cases for AttributeMatcher class"""

    def setUp(self):
        """Set up test fixtures"""
        self.matcher = AttributeMatcher()

    # === Existence operators ===

    def test_exists_operator_success(self):
        """Test exists operator with existing field"""
        attrib = {"a": {"status": "active"}}
        req = AttributeRequirement(path="a.status", operator="exists")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_exists_operator_failure(self):
        """Test exists operator with missing field"""
        attrib = {"a": {"other": "value"}}
        req = AttributeRequirement(path="a.status", operator="exists")

        self.assertFalse(self.matcher.matches(attrib, req))

    def test_not_exists_operator_success(self):
        """Test not_exists operator with missing field"""
        attrib = {"a": {"other": "value"}}
        req = AttributeRequirement(path="a.status", operator="not_exists")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_not_exists_operator_failure(self):
        """Test not_exists operator with existing field"""
        attrib = {"a": {"status": "active"}}
        req = AttributeRequirement(path="a.status", operator="not_exists")

        self.assertFalse(self.matcher.matches(attrib, req))

    # === Comparison operators ===

    def test_equals_operator_success(self):
        """Test equals operator with matching value"""
        attrib = {"a": {"status": "active"}}
        req = AttributeRequirement(path="a.status", operator="equals", value="active")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_equals_operator_failure(self):
        """Test equals operator with non-matching value"""
        attrib = {"a": {"status": "inactive"}}
        req = AttributeRequirement(path="a.status", operator="equals", value="active")

        self.assertFalse(self.matcher.matches(attrib, req))

    def test_equals_operator_type_coercion(self):
        """Test equals operator with type coercion"""
        attrib = {"a": {"count": 42}}
        req = AttributeRequirement(path="a.count", operator="equals", value="42")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_not_equals_operator_success(self):
        """Test not_equals operator with different value"""
        attrib = {"a": {"status": "active"}}
        req = AttributeRequirement(path="a.status", operator="not_equals", value="inactive")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_not_equals_operator_failure(self):
        """Test not_equals operator with matching value"""
        attrib = {"a": {"status": "active"}}
        req = AttributeRequirement(path="a.status", operator="not_equals", value="active")

        self.assertFalse(self.matcher.matches(attrib, req))

    # === Numeric operators ===

    def test_gt_operator_success(self):
        """Test gt operator with greater value"""
        attrib = {"a": {"score": 100}}
        req = AttributeRequirement(path="a.score", operator="gt", value=50)

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_gt_operator_failure(self):
        """Test gt operator with lesser value"""
        attrib = {"a": {"score": 30}}
        req = AttributeRequirement(path="a.score", operator="gt", value=50)

        self.assertFalse(self.matcher.matches(attrib, req))

    def test_gte_operator_equal(self):
        """Test gte operator with equal value"""
        attrib = {"a": {"score": 50}}
        req = AttributeRequirement(path="a.score", operator="gte", value=50)

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_lt_operator_success(self):
        """Test lt operator with lesser value"""
        attrib = {"a": {"score": 30}}
        req = AttributeRequirement(path="a.score", operator="lt", value=50)

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_lte_operator_equal(self):
        """Test lte operator with equal value"""
        attrib = {"a": {"score": 50}}
        req = AttributeRequirement(path="a.score", operator="lte", value=50)

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_numeric_comparison_with_dates(self):
        """Test numeric comparison works with ISO date strings"""
        attrib = {"a": {"validUntil": "2025-12-31"}}
        req = AttributeRequirement(path="a.validUntil", operator="gte", value="2024-01-01")

        self.assertTrue(self.matcher.matches(attrib, req))

    # === String operators ===

    def test_contains_operator_success(self):
        """Test contains operator with substring"""
        attrib = {"a": {"name": "Healthcare Provider"}}
        req = AttributeRequirement(path="a.name", operator="contains", value="Provider")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_contains_operator_failure(self):
        """Test contains operator without substring"""
        attrib = {"a": {"name": "Healthcare Provider"}}
        req = AttributeRequirement(path="a.name", operator="contains", value="Issuer")

        self.assertFalse(self.matcher.matches(attrib, req))

    def test_starts_with_operator_success(self):
        """Test starts_with operator with matching prefix"""
        attrib = {"a": {"lei": "LEI1234567890"}}
        req = AttributeRequirement(path="a.lei", operator="starts_with", value="LEI")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_starts_with_operator_failure(self):
        """Test starts_with operator with non-matching prefix"""
        attrib = {"a": {"lei": "OTHER1234567890"}}
        req = AttributeRequirement(path="a.lei", operator="starts_with", value="LEI")

        self.assertFalse(self.matcher.matches(attrib, req))

    def test_ends_with_operator_success(self):
        """Test ends_with operator with matching suffix"""
        attrib = {"a": {"email": "user@example.com"}}
        req = AttributeRequirement(path="a.email", operator="ends_with", value="@example.com")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_regex_operator_success(self):
        """Test regex operator with matching pattern"""
        attrib = {"a": {"phone": "+1-555-123-4567"}}
        req = AttributeRequirement(path="a.phone", operator="regex", value=r"\+\d-\d{3}-\d{3}-\d{4}")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_regex_operator_failure(self):
        """Test regex operator with non-matching pattern"""
        attrib = {"a": {"phone": "invalid"}}
        req = AttributeRequirement(path="a.phone", operator="regex", value=r"\+\d-\d{3}-\d{3}-\d{4}")

        self.assertFalse(self.matcher.matches(attrib, req))

    def test_regex_operator_invalid_pattern(self):
        """Test regex operator with invalid pattern returns False"""
        attrib = {"a": {"value": "test"}}
        req = AttributeRequirement(path="a.value", operator="regex", value="[invalid")

        self.assertFalse(self.matcher.matches(attrib, req))

    # === Collection operators ===

    def test_in_operator_success(self):
        """Test in operator with value in list"""
        attrib = {"a": {"role": "admin"}}
        req = AttributeRequirement(path="a.role", operator="in", value=["admin", "moderator", "user"])

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_in_operator_failure(self):
        """Test in operator with value not in list"""
        attrib = {"a": {"role": "guest"}}
        req = AttributeRequirement(path="a.role", operator="in", value=["admin", "moderator", "user"])

        self.assertFalse(self.matcher.matches(attrib, req))

    def test_not_in_operator_success(self):
        """Test not_in operator with value not in list"""
        attrib = {"a": {"role": "admin"}}
        req = AttributeRequirement(path="a.role", operator="not_in", value=["banned", "suspended"])

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_not_in_operator_failure(self):
        """Test not_in operator with value in list"""
        attrib = {"a": {"role": "banned"}}
        req = AttributeRequirement(path="a.role", operator="not_in", value=["banned", "suspended"])

        self.assertFalse(self.matcher.matches(attrib, req))

    # === Nested path access ===

    def test_deeply_nested_path(self):
        """Test accessing deeply nested values"""
        attrib = {"a": {"b": {"c": {"d": "deep_value"}}}}
        req = AttributeRequirement(path="a.b.c.d", operator="equals", value="deep_value")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_array_index_access(self):
        """Test accessing array elements by index"""
        attrib = {"a": {"items": ["first", "second", "third"]}}
        req = AttributeRequirement(path="a.items.1", operator="equals", value="second")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_missing_nested_path(self):
        """Test missing nested path returns None"""
        attrib = {"a": {"b": {}}}
        req = AttributeRequirement(path="a.b.c.d", operator="exists")

        self.assertFalse(self.matcher.matches(attrib, req))

    # === Special values ===

    def test_special_value_today(self):
        """Test ${today} special value"""
        today = date.today().isoformat()
        attrib = {"a": {"date": today}}
        req = AttributeRequirement(path="a.date", operator="equals", value="${today}")

        self.assertTrue(self.matcher.matches(attrib, req))

    def test_special_value_gte_today(self):
        """Test comparison with ${today}"""
        future_date = "2099-12-31"
        attrib = {"a": {"validUntil": future_date}}
        req = AttributeRequirement(path="a.validUntil", operator="gte", value="${today}")

        self.assertTrue(self.matcher.matches(attrib, req))

    # === Validate all ===

    def test_validate_all_success(self):
        """Test validate_all with all passing requirements"""
        attrib = {"a": {"status": "active", "score": 100, "type": "provider"}}
        requirements = [
            AttributeRequirement(path="a.status", operator="equals", value="active"),
            AttributeRequirement(path="a.score", operator="gte", value=50),
            AttributeRequirement(path="a.type", operator="exists"),
        ]

        errors = self.matcher.validate_all(attrib, requirements)

        self.assertEqual(errors, [])

    def test_validate_all_with_failures(self):
        """Test validate_all with some failing requirements"""
        attrib = {"a": {"status": "inactive", "score": 30}}
        requirements = [
            AttributeRequirement(path="a.status", operator="equals", value="active"),
            AttributeRequirement(path="a.score", operator="gte", value=50),
            AttributeRequirement(path="a.missing", operator="exists"),
        ]

        errors = self.matcher.validate_all(attrib, requirements)

        self.assertEqual(len(errors), 3)

    # === Edge cases ===

    def test_empty_attrib(self):
        """Test with empty attribute dict"""
        attrib = {}
        req = AttributeRequirement(path="a.field", operator="exists")

        self.assertFalse(self.matcher.matches(attrib, req))

    def test_empty_path(self):
        """Test with empty path"""
        attrib = {"a": {"field": "value"}}
        req = AttributeRequirement(path="", operator="exists")

        self.assertFalse(self.matcher.matches(attrib, req))

    def test_unknown_operator(self):
        """Test with unknown operator returns False"""
        attrib = {"a": {"field": "value"}}
        req = AttributeRequirement(path="a.field", operator="unknown_op", value="value")

        self.assertFalse(self.matcher.matches(attrib, req))

    def test_case_insensitive_operator(self):
        """Test operator is case-insensitive"""
        attrib = {"a": {"status": "active"}}
        req = AttributeRequirement(path="a.status", operator="EQUALS", value="active")

        self.assertTrue(self.matcher.matches(attrib, req))


if __name__ == "__main__":
    unittest.main()
