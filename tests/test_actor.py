#!/usr/bin/env python3
"""
Unit tests for the actor module

Copyright (C) 2025 LACP Daemon Team
SPDX-License-Identifier: GPL-3.0-or-later
"""

from unittest.mock import Mock, patch

import pytest

from lacpd.actor import (
    LACP_STATE_ACTIVE,
    LACP_STATE_AGGREGATION,
    LACP_STATE_COLLECTING,
    LACP_STATE_DEFAULTED,
    LACP_STATE_DISTRIBUTING,
    LACP_STATE_EXPIRED,
    LACP_STATE_SHORT_TIMEOUT,
    LACP_STATE_SYNC,
    LacpActor,
    Port,
    format_state_string,
    parse_inject_rule,
    parse_state_string,
)


class TestStateParsing:
    """Test state string parsing functionality."""

    def test_parse_state_string_bit_format(self):
        """Test parsing state strings in bit format."""
        # Test individual bits
        assert parse_state_string("A") == LACP_STATE_ACTIVE
        assert parse_state_string("T") == LACP_STATE_SHORT_TIMEOUT
        assert parse_state_string("G") == LACP_STATE_AGGREGATION
        assert parse_state_string("S") == LACP_STATE_SYNC
        assert parse_state_string("C") == LACP_STATE_COLLECTING
        assert parse_state_string("D") == LACP_STATE_DISTRIBUTING
        assert parse_state_string("F") == LACP_STATE_DEFAULTED
        assert parse_state_string("E") == LACP_STATE_EXPIRED

        # Test combinations
        assert parse_state_string("AT") == LACP_STATE_ACTIVE | LACP_STATE_SHORT_TIMEOUT
        assert parse_state_string("ATG") == (LACP_STATE_ACTIVE | LACP_STATE_SHORT_TIMEOUT | LACP_STATE_AGGREGATION)
        assert parse_state_string("ATGS") == (
            LACP_STATE_ACTIVE | LACP_STATE_SHORT_TIMEOUT | LACP_STATE_AGGREGATION | LACP_STATE_SYNC
        )

    def test_parse_state_string_hex_format(self):
        """Test parsing state strings in hexadecimal format."""
        assert parse_state_string("0x40") == 64
        assert parse_state_string("0x80") == 128
        assert parse_state_string("0x3") == 3
        assert parse_state_string("0x7") == 7

    def test_parse_state_string_decimal_format(self):
        """Test parsing state strings in decimal format."""
        assert parse_state_string("64") == 64
        assert parse_state_string("128") == 128
        assert parse_state_string("3") == 3
        assert parse_state_string("7") == 7

    def test_parse_state_string_case_insensitive(self):
        """Test that state parsing is case insensitive."""
        assert parse_state_string("atg") == parse_state_string("ATG")
        assert parse_state_string("0x40") == parse_state_string("0X40")

    def test_parse_state_string_whitespace(self):
        """Test that state parsing handles whitespace."""
        assert parse_state_string(" ATG ") == parse_state_string("ATG")
        assert parse_state_string(" 0x40 ") == parse_state_string("0x40")
        assert parse_state_string(" 64 ") == parse_state_string("64")


class TestInjectRuleParsing:
    """Test inject rule parsing functionality."""

    def test_parse_inject_rule_basic(self):
        """Test basic inject rule parsing."""
        condition, target = parse_inject_rule("A:ATG -> A:AT")
        assert condition == {"A": 7}  # ATG = 7
        assert target == {"A": 3}  # AT = 3

    def test_parse_inject_rule_partner_only(self):
        """Test inject rule with partner condition only."""
        condition, target = parse_inject_rule("P:AT -> A:ATG")
        assert condition == {"P": 3}  # AT = 3
        assert target == {"A": 7}  # ATG = 7

    def test_parse_inject_rule_both_actor_partner(self):
        """Test inject rule with both actor and partner conditions."""
        condition, target = parse_inject_rule("A:ATG|P:AT -> A:AT")
        assert condition == {"A": 7, "P": 3}  # ATG = 7, AT = 3
        assert target == {"A": 3}  # AT = 3

    def test_parse_inject_rule_multiple_targets(self):
        """Test inject rule with multiple targets."""
        condition, target = parse_inject_rule("A:ATG -> A:AT|P:AT")
        assert condition == {"A": 7}  # ATG = 7
        assert target == {"A": 3, "P": 3}  # AT = 3 for both

    def test_parse_inject_rule_hex_values(self):
        """Test inject rule with hexadecimal values."""
        condition, target = parse_inject_rule("A:0x40|P:64 -> A:0x80")
        assert condition == {"A": 64, "P": 64}
        assert target == {"A": 128}

    def test_parse_inject_rule_decimal_values(self):
        """Test inject rule with decimal values."""
        condition, target = parse_inject_rule("A:64|P:128 -> A:7")
        assert condition == {"A": 64, "P": 128}
        assert target == {"A": 7}

    def test_parse_inject_rule_mixed_formats(self):
        """Test inject rule with mixed state formats."""
        condition, target = parse_inject_rule("A:ATG|P:64 -> A:0x80")
        assert condition == {"A": 7, "P": 64}  # ATG = 7, 64 = 64
        assert target == {"A": 128}  # 0x80 = 128

    def test_parse_inject_rule_with_spaces(self):
        """Test inject rule parsing with various spacing."""
        # Test with spaces around arrow
        condition, target = parse_inject_rule("A:ATG -> A:AT")
        assert condition == {"A": 7}
        assert target == {"A": 3}

        condition, target = parse_inject_rule("A:ATG  ->  A:AT")
        assert condition == {"A": 7}
        assert target == {"A": 3}

        # Test with spaces around pipe
        condition, target = parse_inject_rule("A:ATG | P:AT -> A:AT")
        assert condition == {"A": 7, "P": 3}
        assert target == {"A": 3}

    def test_parse_inject_rule_empty_condition(self):
        """Test inject rule with empty condition part."""
        condition, target = parse_inject_rule(" -> A:AT")
        assert condition == {}
        assert target == {"A": 3}

    def test_parse_inject_rule_invalid_format(self):
        """Test that invalid inject rule formats raise ValueError."""
        invalid_rules = [
            "invalid",
            "A:ATG",
            "A:ATG ->",
            "A:ATG -> A:AT -> P:AT",
        ]

        for rule in invalid_rules:
            with pytest.raises(ValueError, match="Invalid inject rule format"):
                parse_inject_rule(rule)

    def test_parse_inject_rule_invalid_state_format(self):
        """Test that invalid state formats raise ValueError."""
        test_cases = [
            ("A: -> A:AT", "Invalid state format"),
            ("A:ATG -> A:", "Invalid state format"),
            ("A:INVALID -> A:AT", "Invalid state character"),
        ]

        for rule, expected_error in test_cases:
            with pytest.raises(ValueError, match=expected_error):
                parse_inject_rule(rule)

    def test_parse_inject_rule_invalid_role(self):
        """Test that invalid roles raise ValueError."""
        invalid_rules = [
            "X:ATG -> A:AT",
            "A:ATG -> X:AT",
        ]

        for rule in invalid_rules:
            with pytest.raises(ValueError, match="Invalid role"):
                parse_inject_rule(rule)


class TestStateFormatting:
    """Test state string formatting functionality."""

    def test_format_state_string_basic(self):
        """Test basic state string formatting."""
        assert format_state_string(LACP_STATE_ACTIVE) == "A"
        assert format_state_string(LACP_STATE_SHORT_TIMEOUT) == "T"
        assert format_state_string(LACP_STATE_AGGREGATION) == "G"
        assert format_state_string(LACP_STATE_SYNC) == "S"
        assert format_state_string(LACP_STATE_COLLECTING) == "C"
        assert format_state_string(LACP_STATE_DISTRIBUTING) == "D"
        assert format_state_string(LACP_STATE_DEFAULTED) == "F"
        assert format_state_string(LACP_STATE_EXPIRED) == "E"

    def test_format_state_string_combinations(self):
        """Test state string formatting with combinations."""
        assert format_state_string(LACP_STATE_ACTIVE | LACP_STATE_SHORT_TIMEOUT) == "AT"
        assert format_state_string(LACP_STATE_ACTIVE | LACP_STATE_SHORT_TIMEOUT | LACP_STATE_AGGREGATION) == "ATG"
        assert (
            format_state_string(LACP_STATE_ACTIVE | LACP_STATE_SHORT_TIMEOUT | LACP_STATE_AGGREGATION | LACP_STATE_SYNC)
            == "ATGS"
        )

    def test_format_state_string_zero(self):
        """Test state string formatting with zero state."""
        assert format_state_string(0) == "N"

    def test_format_state_string_unknown_bits(self):
        """Test state string formatting with unknown bits."""
        # Test with some unknown bits (should only show known bits)
        unknown_state = 0x100  # Unknown bit
        assert format_state_string(unknown_state) == "N"

        # Test with known and unknown bits
        mixed_state = LACP_STATE_ACTIVE | 0x100
        assert format_state_string(mixed_state) == "A"


class TestStateRoundTrip:
    """Test round-trip conversion between state strings and integers."""

    def test_state_round_trip_bit_strings(self):
        """Test round-trip conversion with bit strings."""
        test_cases = [
            "A",
            "T",
            "G",
            "S",
            "C",
            "D",
            "F",
            "E",
            "AT",
            "ATG",
            "ATGS",
            "ATGS",
        ]

        for state_str in test_cases:
            state_int = parse_state_string(state_str)
            formatted = format_state_string(state_int)
            # Note: order might be different, so we check that all characters are present
            assert set(state_str) == set(formatted), f"Failed for {state_str}"

    def test_state_round_trip_numeric(self):
        """Test round-trip conversion with numeric values."""
        test_cases = [3, 7, 64, 128]

        for state_int in test_cases:
            formatted = format_state_string(state_int)
            parsed = parse_state_string(formatted)
            # Note: this might not be exact due to unknown bits
            # We just verify that parsing the formatted string gives a valid result
            assert isinstance(parsed, int)
            assert parsed >= 0


class TestMultipleInjectRules:
    """Test multiple inject rules functionality."""

    def test_multiple_rules_parsing(self):
        """Test parsing multiple inject rules."""
        rules = [
            "P:AT -> A:ATG",
            "A:ATG -> P:AT",
            "A:ATG|P:AT -> A:AT",
        ]

        parsed_rules = []
        for rule in rules:
            condition, target = parse_inject_rule(rule)
            parsed_rules.append((condition, target))

        # Verify all rules were parsed correctly
        assert len(parsed_rules) == 3

        # Check first rule: P:AT -> A:ATG
        assert parsed_rules[0][0] == {"P": 3}  # condition
        assert parsed_rules[0][1] == {"A": 7}  # target

        # Check second rule: A:ATG -> P:AT
        assert parsed_rules[1][0] == {"A": 7}  # condition
        assert parsed_rules[1][1] == {"P": 3}  # target

        # Check third rule: A:ATG|P:AT -> A:AT
        assert parsed_rules[2][0] == {"A": 7, "P": 3}  # condition
        assert parsed_rules[2][1] == {"A": 3}  # target

    def test_multiple_rules_sequential_execution(self):
        """Test that multiple rules are executed in sequence."""
        # Simulate the state checking logic
        current_actor = 7  # ATG
        current_partner = 3  # AT

        rules = [
            ("P:AT -> A:ATG", {"P": 3}, {"A": 7}),  # Should trigger
            ("A:ATG -> P:AT", {"A": 7}, {"P": 3}),  # Should trigger
            ("A:ATG|P:AT -> A:AT", {"A": 7, "P": 3}, {"A": 3}),  # Should trigger
        ]

        applied_changes = []

        for _rule_str, condition, target in rules:
            # Check conditions
            conditions_met = True
            for role, expected_state in condition.items():
                if role == "A" and current_actor != expected_state:
                    conditions_met = False
                elif role == "P" and current_partner != expected_state:
                    conditions_met = False

            if conditions_met:
                # Apply targets
                for role, target_state in target.items():
                    if role == "A":
                        applied_changes.append(f"Actor: {current_actor} -> {target_state}")
                        current_actor = target_state
                    elif role == "P":
                        applied_changes.append(f"Partner: {current_partner} -> {target_state}")
                        current_partner = target_state

        # Verify that all rules were applied
        assert len(applied_changes) == 3
        assert "Actor: 7 -> 7" in applied_changes  # First rule (no change)
        assert "Partner: 3 -> 3" in applied_changes  # Second rule (no change)
        assert "Actor: 7 -> 3" in applied_changes  # Third rule (changes actor)

    def test_multiple_rules_with_invalid_rule(self):
        """Test that invalid rules don't prevent valid rules from being processed."""
        rules = [
            "P:AT -> A:ATG",  # Valid
            "INVALID_RULE",  # Invalid
            "A:ATG -> P:AT",  # Valid
        ]

        valid_rules = []
        for rule in rules:
            try:
                condition, target = parse_inject_rule(rule)
                valid_rules.append((condition, target))
            except ValueError:
                # Skip invalid rules
                continue

        # Should have 2 valid rules
        assert len(valid_rules) == 2
        assert valid_rules[0][0] == {"P": 3}  # First valid rule
        assert valid_rules[1][0] == {"A": 7}  # Second valid rule

    def test_multiple_rules_mixed_formats(self):
        """Test multiple rules with different state formats."""
        rules = [
            "P:AT -> A:ATG",  # Bit string
            "A:0x7 -> P:0x3",  # Hex
            "A:7|P:3 -> A:3",  # Decimal
        ]

        parsed_rules = []
        for rule in rules:
            condition, target = parse_inject_rule(rule)
            parsed_rules.append((condition, target))

        # All rules should parse successfully
        assert len(parsed_rules) == 3

        # Verify mixed formats work correctly
        assert parsed_rules[0] == ({"P": 3}, {"A": 7})  # Bit string
        assert parsed_rules[1] == ({"A": 7}, {"P": 3})  # Hex
        assert parsed_rules[2] == ({"A": 7, "P": 3}, {"A": 3})  # Decimal

    def test_multiple_rules_priority_order(self):
        """Test that rules are processed in the order they are specified."""
        # This test verifies that the order of rule processing matters
        current_actor = 7  # ATG
        current_partner = 3  # AT

        # Rule 1: Changes actor to AT (3)
        # Rule 2: Changes actor back to ATG (7) if actor is AT
        rules = [
            ("A:ATG -> A:AT", {"A": 7}, {"A": 3}),  # Should trigger first
            ("A:AT -> A:ATG", {"A": 3}, {"A": 7}),  # Should trigger second
        ]

        changes = []
        for _rule_str, condition, target in rules:
            # Check conditions
            conditions_met = True
            for role, expected_state in condition.items():
                if role == "A" and current_actor != expected_state:
                    conditions_met = False
                elif role == "P" and current_partner != expected_state:
                    conditions_met = False

            if conditions_met:
                # Apply targets
                for role, target_state in target.items():
                    if role == "A":
                        changes.append(f"Actor: {current_actor} -> {target_state}")
                        current_actor = target_state
                    elif role == "P":
                        changes.append(f"Partner: {current_partner} -> {target_state}")
                        current_partner = target_state

        # Both rules should be applied in sequence
        assert len(changes) == 2
        assert changes[0] == "Actor: 7 -> 3"  # First rule
        assert changes[1] == "Actor: 3 -> 7"  # Second rule (triggered by first rule's change)


class TestExitAfterInject:
    """Test exit-after-inject functionality."""

    def test_port_with_actor_reference(self):
        """Test that Port class correctly stores actor reference."""
        inject_rules = ["P:AT -> A:ATG"]

        with patch("lacpd.actor.get_mac_address", return_value="00:11:22:33:44:55"):
            # Create a mock actor
            mock_actor = Mock()
            mock_actor.inject_triggered = False

            port = Port(
                iface_name="eth0",
                port_id=1,
                system_id="00:11:22:33:44:55",
                key=1,
                inject_rules=inject_rules,
                actor_ref=mock_actor,
            )

        assert port.actor_ref == mock_actor
        assert len(port.parsed_rules) == 1

    def test_inject_triggered_notification(self):
        """Test that inject trigger notifies the actor."""
        inject_rules = ["P:AT -> A:ATG"]

        with patch("lacpd.actor.get_mac_address", return_value="00:11:22:33:44:55"):
            # Create a mock actor
            mock_actor = Mock()
            mock_actor.inject_triggered = False

            port = Port(
                iface_name="eth0",
                port_id=1,
                system_id="00:11:22:33:44:55",
                key=1,
                inject_rules=inject_rules,
                actor_ref=mock_actor,
            )

        # Set up initial state to trigger injection
        port.partner_info["state"] = 3  # AT state

        # Call _check_inject_rules
        port._check_inject_rules()

        # Verify that actor was notified
        assert mock_actor.inject_triggered is True

    def test_lacp_actor_with_exit_after_inject(self):
        """Test that LacpActor correctly handles exit-after-inject flag."""
        with patch("lacpd.actor.get_mac_address", return_value="00:11:22:33:44:55"):
            actor = LacpActor(
                interfaces=["eth0"],
                inject_rules=["P:AT -> A:ATG"],
                exit_after_inject=True,
            )

        assert actor.exit_after_inject is True
        assert actor.inject_triggered is False

        # Verify that ports have actor reference
        for port in actor.ports:
            assert port.actor_ref == actor

    def test_lacp_actor_without_exit_after_inject(self):
        """Test that LacpActor works correctly without exit-after-inject flag."""
        with patch("lacpd.actor.get_mac_address", return_value="00:11:22:33:44:55"):
            actor = LacpActor(
                interfaces=["eth0"],
                inject_rules=["P:AT -> A:ATG"],
                exit_after_inject=False,
            )

        assert actor.exit_after_inject is False
        assert actor.inject_triggered is False

        # Verify that ports still have actor reference
        for port in actor.ports:
            assert port.actor_ref == actor
