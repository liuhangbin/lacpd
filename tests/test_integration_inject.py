#!/usr/bin/env python3
"""
Integration tests for multiple inject rules functionality
"""

from unittest.mock import patch

from lacpd.actor import Port
from lacpd.main import create_argument_parser


class TestMultipleInjectIntegration:
    """Integration tests for multiple inject rules."""

    def test_port_with_multiple_inject_rules(self):
        """Test that Port class correctly handles multiple inject rules."""
        inject_rules = [
            "P:AT -> A:ATG",
            "A:ATG -> P:AT",
            "A:ATG|P:AT -> A:AT",
        ]

        with patch("lacpd.actor.get_mac_address", return_value="00:11:22:33:44:55"):
            port = Port(
                iface_name="eth0",
                port_id=1,
                system_id="00:11:22:33:44:55",
                key=1,
                inject_rules=inject_rules,
            )

        assert len(port.parsed_rules) == 3

        # Check first rule
        condition1, target1 = port.parsed_rules[0]
        assert condition1 == {"P": 3}
        assert target1 == {"A": 7}

        # Check second rule
        condition2, target2 = port.parsed_rules[1]
        assert condition2 == {"A": 7}
        assert target2 == {"P": 3}

        # Check third rule
        condition3, target3 = port.parsed_rules[2]
        assert condition3 == {"A": 7, "P": 3}
        assert target3 == {"A": 3}

    def test_port_with_mixed_valid_invalid_rules(self):
        """Test that Port class handles mixed valid and invalid rules correctly."""
        inject_rules = [
            "P:AT -> A:ATG",  # Valid
            "INVALID_RULE",  # Invalid
            "A:ATG -> P:AT",  # Valid
        ]

        with patch("lacpd.actor.get_mac_address", return_value="00:11:22:33:44:55"):
            port = Port(
                iface_name="eth0",
                port_id=1,
                system_id="00:11:22:33:44:55",
                key=1,
                inject_rules=inject_rules,
            )

        # Should have 2 valid rules (invalid rule should be skipped)
        assert len(port.parsed_rules) == 2

        # Check valid rules
        condition1, target1 = port.parsed_rules[0]
        assert condition1 == {"P": 3}
        assert target1 == {"A": 7}

        condition2, target2 = port.parsed_rules[1]
        assert condition2 == {"A": 7}
        assert target2 == {"P": 3}

    def test_argument_parser_multiple_inject_rules(self):
        """Test that argument parser correctly handles multiple inject rules."""
        parser = create_argument_parser()

        args = parser.parse_args(
            [
                "-i",
                "eth0",
                "--inject",
                "P:AT -> A:ATG",
                "--inject",
                "A:ATG -> P:AT",
                "--inject",
                "A:ATG|P:AT -> A:AT",
            ]
        )

        assert args.inject == ["P:AT -> A:ATG", "A:ATG -> P:AT", "A:ATG|P:AT -> A:AT"]
        assert args.interfaces == ["eth0"]

    def test_multiple_rules_execution_simulation(self):
        """Simulate the execution of multiple inject rules."""
        current_actor_state = 7  # ATG
        current_partner_state = 3  # AT

        rules = [
            ("P:AT -> A:ATG", {"P": 3}, {"A": 7}),
            ("A:ATG -> P:AT", {"A": 7}, {"P": 3}),
            ("A:ATG|P:AT -> A:AT", {"A": 7, "P": 3}, {"A": 3}),
        ]

        applied_changes = []

        for _rule_str, condition, target in rules:
            conditions_met = True
            for role, expected_state in condition.items():
                if role == "A" and current_actor_state != expected_state:
                    conditions_met = False
                elif role == "P" and current_partner_state != expected_state:
                    conditions_met = False

            if conditions_met:
                for role, target_state in target.items():
                    if role == "A":
                        old_state = current_actor_state
                        current_actor_state = target_state
                        applied_changes.append(f"Actor: {old_state} -> {target_state}")
                    elif role == "P":
                        old_state = current_partner_state
                        current_partner_state = target_state
                        applied_changes.append(f"Partner: {old_state} -> {target_state}")

        assert len(applied_changes) == 3
        assert "Actor: 7 -> 7" in applied_changes
        assert "Actor: 7 -> 3" in applied_changes
        assert "Partner: 3 -> 3" in applied_changes

        assert current_actor_state == 3
        assert current_partner_state == 3
