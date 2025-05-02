"""
Debugging test to check enum behavior issues.
"""

from enum import Enum

import pytest


class ComparisonOperator(str, Enum):
    """Comparison operators for rule conditions."""
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"


@pytest.mark.standalone()
def test_enum_behavior():
    """Test the behavior of Enum classes."""
    print("\nDEBUG: Testing enum behavior")

    # 1. Create an enum instance
    op1 = ComparisonOperator.GREATER_THAN_OR_EQUAL
    op2 = ComparisonOperator.GREATER_THAN_OR_EQUAL

    # 2. Print the instance, its type, and its value
    print(f"op1: {op1}, type: {type(op1)}, value: {op1.value}")
    print(f"op2: {op2}, type: {type(op2)}, value: {op2.value}")

    # 3. Check if the instances are equal
    print(f"op1 == op2: {op1 == op2}")
    print(f"op1 is op2: {op1 is op2}")

    # 4. Create another instance with the same value
    op3 = ComparisonOperator("greater_than_or_equal")
    print(f"op3: {op3}, type: {type(op3)}, value: {op3.value}")
    print(f"op1 == op3: {op1 == op3}")
    print(f"op1 is op3: {op1 is op3}")

    # 5. Check comparison with string
    print(f"op1 == 'greater_than_or_equal': {op1 == 'greater_than_or_equal'}")
    print(f"op1.value == 'greater_than_or_equal': {op1.value == 'greater_than_or_equal'}")

    # 6. Force the test to pass or fail based on expected behavior
    assert op1 == op2
    assert op1 == op3
    assert op1 == "greater_than_or_equal"  # This is key!


def simulate_rule_evaluation():
    """Simulate the rule evaluation with the enum."""
    print("\nDEBUG: Simulating rule evaluation")

    # Mimic the rule and data point
    operator = ComparisonOperator.GREATER_THAN_OR_EQUAL
    threshold = 100
    value = 100

    # Check different ways of comparing
    print(f"Method 1 (direct ==): {operator == ComparisonOperator.GREATER_THAN_OR_EQUAL}")
    print(f"Method 2 (is): {operator is ComparisonOperator.GREATER_THAN_OR_EQUAL}")
    print(f"Method 3 (string ==): {operator == 'greater_than_or_equal'}")
    print(f"Method 4 (value ==): {operator.value == 'greater_than_or_equal'}")

    # Different comparison operators
    if operator == ComparisonOperator.GREATER_THAN:
        result = value > threshold
    elif operator == ComparisonOperator.GREATER_THAN_OR_EQUAL:
        result = value >= threshold
    elif operator == ComparisonOperator.LESS_THAN:
        result = value < threshold
    elif operator == ComparisonOperator.LESS_THAN_OR_EQUAL:
        result = value <= threshold
    elif operator == ComparisonOperator.EQUAL:
        result = value == threshold
    elif operator == ComparisonOperator.NOT_EQUAL:
        result = value != threshold
    else:
        result = False

    print(f"Result of comparison: {result}")
    return result


@pytest.mark.standalone()
def test_rule_evaluation():
    """Test the rule evaluation simulation."""
    result = simulate_rule_evaluation()
    assert result is True  # 100 >= 100 should be True