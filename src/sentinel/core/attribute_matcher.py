# -*- encoding: utf-8 -*-
"""
sentinel.core.attribute_matcher module

Evaluates attribute requirements against credential payloads.

"""

import re
from datetime import date, datetime
from typing import Any, List, Optional

from sentinel.core.roots_of_trust import AttributeRequirement


class AttributeMatcher:
    """
    Evaluates attribute requirements against credential payloads.

    Supports multiple comparison operators and special values like ${now} and ${today}.

    Example:
        matcher = AttributeMatcher()
        requirement = AttributeRequirement(path="a.status", operator="equals", value="active")
        result = matcher.matches({"a": {"status": "active"}}, requirement)
    """

    # Special value patterns
    SPECIAL_VALUES = {
        "${now}": lambda: datetime.utcnow().isoformat(),
        "${today}": lambda: date.today().isoformat(),
    }

    def matches(self, attrib: dict, requirement: AttributeRequirement) -> bool:
        """
        Check if the attribute matches the requirement.

        Args:
            attrib: The credential attributes dictionary
            requirement: The attribute requirement to check

        Returns:
            True if the attribute matches the requirement, False otherwise
        """
        actual_value = self._get_nested_value(attrib, requirement.path)
        expected_value = self._resolve_special_value(requirement.value)

        operator = requirement.operator.lower()

        # Existence operators
        if operator == "exists":
            return actual_value is not None
        if operator == "not_exists":
            return actual_value is None

        # For all other operators, we need the value to exist
        if actual_value is None:
            return False

        # Comparison operators
        if operator == "equals":
            return self._compare_equals(actual_value, expected_value)
        if operator == "not_equals":
            return not self._compare_equals(actual_value, expected_value)

        # Numeric operators
        if operator == "gt":
            return self._compare_numeric(actual_value, expected_value, lambda a, b: a > b)
        if operator == "gte":
            return self._compare_numeric(actual_value, expected_value, lambda a, b: a >= b)
        if operator == "lt":
            return self._compare_numeric(actual_value, expected_value, lambda a, b: a < b)
        if operator == "lte":
            return self._compare_numeric(actual_value, expected_value, lambda a, b: a <= b)

        # String operators
        if operator == "contains":
            return self._compare_string_contains(actual_value, expected_value)
        if operator == "starts_with":
            return self._compare_string_starts_with(actual_value, expected_value)
        if operator == "ends_with":
            return self._compare_string_ends_with(actual_value, expected_value)
        if operator == "regex":
            return self._compare_regex(actual_value, expected_value)

        # Collection operators
        if operator == "in":
            return self._compare_in(actual_value, expected_value)
        if operator == "not_in":
            return not self._compare_in(actual_value, expected_value)

        # Unknown operator
        return False

    def validate_all(
        self, attrib: dict, requirements: List[AttributeRequirement]
    ) -> List[str]:
        """
        Validate all attribute requirements and return a list of errors.

        Args:
            attrib: The credential attributes dictionary
            requirements: List of attribute requirements to check

        Returns:
            List of error messages for failed requirements (empty if all pass)
        """
        errors = []
        for req in requirements:
            if not self.matches(attrib, req):
                actual_value = self._get_nested_value(attrib, req.path)
                expected_value = self._resolve_special_value(req.value)
                errors.append(
                    f"Attribute '{req.path}' failed {req.operator} check: "
                    f"expected {expected_value!r}, got {actual_value!r}"
                )
        return errors

    def _get_nested_value(self, data: dict, path: str) -> Any:
        """
        Get a nested value from a dictionary using dot notation.

        Args:
            data: The dictionary to search
            path: Dot-notation path (e.g., "a.fieldName")

        Returns:
            The value at the path, or None if not found
        """
        if not data or not path:
            return None

        parts = path.split(".")
        current = data

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    index = int(part)
                    current = current[index]
                except (ValueError, IndexError):
                    return None
            else:
                return None

            if current is None:
                return None

        return current

    def _resolve_special_value(self, value: Any) -> Any:
        """
        Resolve special value patterns like ${now} and ${today}.

        Args:
            value: The value to resolve

        Returns:
            The resolved value
        """
        if isinstance(value, str):
            if value in self.SPECIAL_VALUES:
                return self.SPECIAL_VALUES[value]()
        return value

    def _compare_equals(self, actual: Any, expected: Any) -> bool:
        """Compare two values for equality, handling type coercion."""
        if type(actual) == type(expected):
            return actual == expected

        # Try string comparison
        return str(actual) == str(expected)

    def _compare_numeric(self, actual: Any, expected: Any, comparator) -> bool:
        """Compare values numerically or as strings (for dates)."""
        try:
            # Try numeric comparison
            actual_num = float(actual) if not isinstance(actual, (int, float)) else actual
            expected_num = float(expected) if not isinstance(expected, (int, float)) else expected
            return comparator(actual_num, expected_num)
        except (ValueError, TypeError):
            pass

        # Try string comparison (works for ISO dates)
        try:
            return comparator(str(actual), str(expected))
        except (ValueError, TypeError):
            return False

    def _compare_string_contains(self, actual: Any, expected: Any) -> bool:
        """Check if actual contains expected."""
        return str(expected) in str(actual)

    def _compare_string_starts_with(self, actual: Any, expected: Any) -> bool:
        """Check if actual starts with expected."""
        return str(actual).startswith(str(expected))

    def _compare_string_ends_with(self, actual: Any, expected: Any) -> bool:
        """Check if actual ends with expected."""
        return str(actual).endswith(str(expected))

    def _compare_regex(self, actual: Any, pattern: Any) -> bool:
        """Check if actual matches the regex pattern."""
        try:
            return bool(re.match(str(pattern), str(actual)))
        except re.error:
            return False

    def _compare_in(self, actual: Any, expected: Any) -> bool:
        """Check if actual is in expected (expected should be a list)."""
        if isinstance(expected, list):
            return actual in expected or str(actual) in [str(e) for e in expected]
        return False
