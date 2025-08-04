#!/usr/bin/env python3
"""
Unit tests for the main module

Copyright (C) 2025 LACP Daemon Team
SPDX-License-Identifier: GPL-3.0-or-later
"""

import argparse
import sys
from unittest.mock import patch, MagicMock

import pytest

from lacpd.main import create_argument_parser, validate_arguments
from lacpd.actor import LACP_RATE_FAST, LACP_RATE_SLOW


class TestArgumentParser:
    """Test argument parser creation."""

    def test_create_argument_parser(self):
        """Test that argument parser is created correctly."""
        parser = create_argument_parser()
        assert isinstance(parser, argparse.ArgumentParser)
        assert parser.description == "LACP Active Simulator Daemon"


class TestArgumentValidation:
    """Test argument validation logic."""

    def test_valid_status_query(self):
        """Test valid status query arguments."""
        parser = create_argument_parser()

        # Basic status query
        args = parser.parse_args(["-s"])
        validate_arguments(args)

        # Status query with log level
        args = parser.parse_args(["-s", "--log-level", "DEBUG"])
        validate_arguments(args)

        # Status query with JSON output
        args = parser.parse_args(["-s", "-j"])
        validate_arguments(args)

        # Status query with pretty output
        args = parser.parse_args(["-s", "-p"])
        validate_arguments(args)

        # Status query with namespace filter
        args = parser.parse_args(["-s", "-n", "test_ns"])
        validate_arguments(args)

        # Status query with interface filter
        args = parser.parse_args(["-s", "-i", "eth0"])
        validate_arguments(args)

        # Status query with multiple filters
        args = parser.parse_args(["-s", "-n", "test_ns", "-i", "eth0", "-j"])
        validate_arguments(args)

    def test_invalid_status_query_with_daemon_options(self):
        """Test that daemon options are rejected with status query."""
        parser = create_argument_parser()

        # Status query with rate option
        args = parser.parse_args(["-s", "--rate", "slow"])
        with pytest.raises(SystemExit, match="Daemon options cannot be used with -s/--status"):
            validate_arguments(args)

        # Status query with passive option
        args = parser.parse_args(["-s", "--passive"])
        with pytest.raises(SystemExit, match="Daemon options cannot be used with -s/--status"):
            validate_arguments(args)

        # Status query with daemon option
        args = parser.parse_args(["-s", "-d"])
        with pytest.raises(SystemExit, match="Daemon options cannot be used with -s/--status"):
            validate_arguments(args)

        # Status query with multiple daemon options
        args = parser.parse_args(["-s", "--rate", "slow", "--passive"])
        with pytest.raises(SystemExit, match="Daemon options cannot be used with -s/--status"):
            validate_arguments(args)

    def test_valid_kill_command(self):
        """Test valid kill command arguments."""
        parser = create_argument_parser()

        # Basic kill command
        args = parser.parse_args(["-k"])
        validate_arguments(args)

        # Kill command with namespace
        args = parser.parse_args(["-k", "-n", "test_ns"])
        validate_arguments(args)

    def test_invalid_kill_command(self):
        """Test that invalid options are rejected with kill command."""
        parser = create_argument_parser()

        # Kill command with JSON output
        args = parser.parse_args(["-k", "-j"])
        with pytest.raises(SystemExit, match="Output format options cannot be used with -k/--kill"):
            validate_arguments(args)

        # Kill command with daemon options
        args = parser.parse_args(["-k", "--rate", "slow"])
        with pytest.raises(SystemExit, match="Daemon options cannot be used with -k/--kill"):
            validate_arguments(args)

    def test_valid_daemon_start(self):
        """Test valid daemon start arguments."""
        parser = create_argument_parser()

        # Basic daemon start
        args = parser.parse_args(["-i", "eth0"])
        validate_arguments(args)

        # Daemon start with multiple interfaces
        args = parser.parse_args(["-i", "eth0", "-i", "eth1"])
        validate_arguments(args)

        # Daemon start with rate option
        args = parser.parse_args(["-i", "eth0", "--rate", "slow"])
        validate_arguments(args)

        # Daemon start with passive mode
        args = parser.parse_args(["-i", "eth0", "--passive"])
        validate_arguments(args)

        # Daemon start with daemon mode
        args = parser.parse_args(["-i", "eth0", "-d"])
        validate_arguments(args)

        # Daemon start with log level
        args = parser.parse_args(["-i", "eth0", "--log-level", "DEBUG"])
        validate_arguments(args)

        # Daemon start with all options
        args = parser.parse_args([
            "-i", "eth0", "-i", "eth1",
            "--rate", "slow",
            "--passive",
            "-d",
            "--log-level", "DEBUG"
        ])
        validate_arguments(args)

    def test_invalid_daemon_start(self):
        """Test that invalid options are rejected with daemon start."""
        parser = create_argument_parser()

        # Daemon start with JSON output
        args = parser.parse_args(["-i", "eth0", "-j"])
        with pytest.raises(SystemExit, match="Output format and filtering options can only be used with -s/--status"):
            validate_arguments(args)

        # Daemon start with pretty output
        args = parser.parse_args(["-i", "eth0", "-p"])
        with pytest.raises(SystemExit, match="Output format and filtering options can only be used with -s/--status"):
            validate_arguments(args)

        # Daemon start with namespace filter
        args = parser.parse_args(["-i", "eth0", "-n", "test_ns"])
        with pytest.raises(SystemExit, match="Output format and filtering options can only be used with -s/--status"):
            validate_arguments(args)


class TestArgumentParserEdgeCases:
    """Test edge cases in argument parsing."""

    def test_mutually_exclusive_actions(self):
        """Test that mutually exclusive actions are enforced."""
        parser = create_argument_parser()

        # Cannot specify multiple actions
        with pytest.raises(SystemExit):
            parser.parse_args(["-s", "-k"])

        # These combinations are now valid
        args = parser.parse_args(["-s", "-i", "eth0"])
        assert args.status is True
        assert args.interfaces == ["eth0"]

        args = parser.parse_args(["-k", "-i", "eth0"])
        assert args.kill is True
        assert args.interfaces == ["eth0"]

    def test_mutually_exclusive_output_formats(self):
        """Test that mutually exclusive output formats are enforced."""
        parser = create_argument_parser()

        # Cannot specify both JSON and pretty output
        with pytest.raises(SystemExit):
            parser.parse_args(["-s", "-j", "-p"])

    def test_rate_option_values(self):
        """Test that rate option accepts correct values."""
        parser = create_argument_parser()

        # Valid rate values
        args = parser.parse_args(["-i", "eth0", "--rate", "fast"])
        assert args.rate == LACP_RATE_FAST

        args = parser.parse_args(["-i", "eth0", "--rate", "slow"])
        assert args.rate == LACP_RATE_SLOW

        # Invalid rate value
        with pytest.raises(SystemExit):
            parser.parse_args(["-i", "eth0", "--rate", "invalid"])

    def test_log_level_values(self):
        """Test that log level option accepts correct values."""
        parser = create_argument_parser()

        # Valid log levels
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        for level in valid_levels:
            args = parser.parse_args(["-s", "--log-level", level])
            assert args.log_level == level

        # Invalid log level
        with pytest.raises(SystemExit):
            parser.parse_args(["-s", "--log-level", "INVALID"])

    def test_log_file_option(self):
        """Test that log file option accepts correct values."""
        parser = create_argument_parser()

        # Valid log file paths
        test_files = ["/tmp/test.log", "test.log", "./logs/app.log", "/var/log/lacpd.log"]
        for log_file in test_files:
            args = parser.parse_args(["-s", "--log-file", log_file])
            assert args.log_file == log_file

        # Test with different actions
        args = parser.parse_args(["-k", "--log-file", "kill.log"])
        assert args.log_file == "kill.log"

        args = parser.parse_args(["-i", "eth0", "--log-file", "daemon.log"])
        assert args.log_file == "daemon.log"

    def test_required_arguments(self):
        """Test that required arguments are enforced."""
        parser = create_argument_parser()

        # Missing required argument - now handled in validation
        args = parser.parse_args([])
        with pytest.raises(SystemExit, match="Must specify either -s/--status, -k/--kill, or -i/--interface"):
            validate_arguments(args)

        # Unknown argument
        with pytest.raises(SystemExit):
            parser.parse_args(["--unknown-arg"])


class TestIntegration:
    """Integration tests for argument parsing and validation."""

    def test_complex_argument_combinations(self):
        """Test complex argument combinations that should work."""
        parser = create_argument_parser()

        # Status query with all valid options
        args = parser.parse_args([
            "-s",
            "-j",
            "-n", "test_ns",
            "-i", "eth0",
            "--log-level", "DEBUG",
            "--log-file", "status.log"
        ])
        validate_arguments(args)

        # Daemon start with all valid options
        args = parser.parse_args([
            "-i", "eth0",
            "-i", "eth1",
            "--rate", "slow",
            "--passive",
            "-d",
            "--log-level", "WARNING",
            "--log-file", "daemon.log"
        ])
        validate_arguments(args)

        # Kill command with valid options
        args = parser.parse_args([
            "-k",
            "-n", "test_ns",
            "--log-level", "ERROR",
            "--log-file", "kill.log"
        ])
        validate_arguments(args)