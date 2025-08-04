#!/usr/bin/env python3
"""
LACP Daemon Main Entry Point

This module provides the main entry point for the LACP daemon,
handling command-line argument parsing and daemon lifecycle management.

Copyright (C) 2025 LACP Daemon Team
SPDX-License-Identifier: GPL-3.0-or-later
"""

import argparse
import json
import logging
import sys
import time

from lacpd.actor import (
    LACP_RATE_FAST,
    LACP_RATE_SLOW,
    LACP_STATE_ACTIVE,
    LACP_STATE_AGGREGATION,
    LACP_STATE_COLLECTING,
    LACP_STATE_DEFAULTED,
    LACP_STATE_DISTRIBUTING,
    LACP_STATE_EXPIRED,
    LACP_STATE_SHORT_TIMEOUT,
    LACP_STATE_SYNC,
    LacpActor,
)
from lacpd.utils import (
    daemonize,
    get_daemon_status_from_socket,
    get_socket_paths_for_namespace,
    kill_lacpd_processes,
    setup_logging,
)

# Configure logging
logger = logging.getLogger(__name__)


def query_status(
    as_json: bool = False,
    pretty: bool = False,
    namespace: str | None = None,
    interfaces: list[str] | None = None,
) -> None:
    """
    Query the status of running LACP daemons.

    Args:
        as_json: Output in compact JSON format
        pretty: Output in pretty-printed JSON format
        namespace: Filter by network namespace name
        interfaces: Filter by interface names
    """
    socket_paths = get_socket_paths_for_namespace(namespace)

    if not socket_paths:
        logger.error("No LACP daemons found in the target namespace.")
        return

    all_status_data = []

    for socket_path in socket_paths:
        daemon_status = get_daemon_status_from_socket(socket_path)
        if daemon_status is None:
            continue

        # Filter by interfaces
        if interfaces is not None:
            daemon_ports = daemon_status.get("ports", [])
            matching_ports = [port for port in daemon_ports if port["interface"] in interfaces]

            if not matching_ports:
                continue

            # Create a new daemon status with only matching ports
            filtered_daemon_status = daemon_status.copy()
            filtered_daemon_status["ports"] = matching_ports
            all_status_data.append(filtered_daemon_status)
        else:
            all_status_data.append(daemon_status)

    if not all_status_data:
        logger.error("No matching LACP daemons found.")
        return

    if pretty:
        print(json.dumps(all_status_data, indent=4))
    elif as_json:
        print(json.dumps(all_status_data))
    else:
        _print_human_readable_status(all_status_data)


def _print_human_readable_status(all_status_data: list[dict]) -> None:
    """
    Print status in human-readable format.

    Args:
        all_status_data: List of daemon status dictionaries
    """
    for daemon_status in all_status_data:
        pid = daemon_status.get("pid", "N/A")
        net_ns = daemon_status.get("net_ns_id", "default")
        configured_rate = daemon_status.get("configured_rate_mode", "fast")
        active_mode = daemon_status.get("active_mode", True)
        mode_str = "passive" if not active_mode else "active"

        print(f"--- Daemon PID: {pid} (Namespace: {net_ns}, Mode: {mode_str}, Configured Rate: {configured_rate}) ---")

        for port_status in daemon_status.get("ports", []):
            print(f"  --- Interface: {port_status['interface']} ---")
            print(f"    Mode: {'passive' if not port_status.get('active_mode', True) else 'active'}")
            print(f"    Configured Rate: {port_status.get('configured_rate_mode', 'fast')}")
            print(f"    Effective Rate: {port_status.get('effective_rate_mode', 'fast')}")
            print(f"    Partner Active: {'YES' if port_status.get('partner_active', False) else 'NO'}")
            print(f"    Should Send: {'YES' if port_status.get('should_send', True) else 'NO'}")
            print(f"    Mux State: {port_status['mux_state']}")
            print(f"    Selected: {'YES' if port_status['selected'] else 'NO'}")

            _print_actor_partner_info(port_status)


def _print_actor_partner_info(port_status: dict) -> None:
    """
    Print actor and partner information for a port.

    Args:
        port_status: Port status dictionary
    """

    def format_state(state: int) -> str:
        """Format LACP state bits into human-readable string."""
        bits = []
        if state & LACP_STATE_ACTIVE:
            bits.append("ACTIVE")
        if state & LACP_STATE_SHORT_TIMEOUT:
            bits.append("SHORT_TIMEOUT")
        if state & LACP_STATE_AGGREGATION:
            bits.append("AGGREGATION")
        if state & LACP_STATE_SYNC:
            bits.append("SYNC")
        if state & LACP_STATE_COLLECTING:
            bits.append("COLLECTING")
        if state & LACP_STATE_DISTRIBUTING:
            bits.append("DISTRIBUTING")
        if state & LACP_STATE_DEFAULTED:
            bits.append("DEFAULTED")
        if state & LACP_STATE_EXPIRED:
            bits.append("EXPIRED")
        return f"{state:08b} ({', '.join(bits)})"

    print("    Actor State:")
    print(f"      System: {port_status['actor']['system']} (Prio: {port_status['actor']['system_priority']})")
    print(f"      Port:   {port_status['actor']['port']} (Prio: {port_status['actor']['port_priority']})")
    print(f"      Key:    {port_status['actor']['key']}")
    print(f"      State:  {format_state(port_status['actor']['state'])}")

    print("    Partner State:")
    print(f"      System: {port_status['partner']['system']} (Prio: {port_status['partner']['system_priority']})")
    print(f"      Port:   {port_status['partner']['port']} (Prio: {port_status['partner']['port_priority']})")
    print(f"      Key:    {port_status['partner']['key']}")
    print(f"      State:  {format_state(port_status['partner']['state'])}")


def run_daemon(
    interfaces: list[str],
    rate_mode: str = LACP_RATE_FAST,
    active_mode: bool = True,
    daemon_mode: bool = False,
    log_file: str | None = None,
    inject_rules: list[str] | None = None,
    exit_after_inject: bool = False,
) -> None:
    """
    Run the LACP daemon.

    Args:
        interfaces: List of network interfaces to use
        rate_mode: LACP rate mode ('fast' or 'slow')
        active_mode: Whether to run in active mode
        daemon_mode: Whether to run as a background daemon
    """
    # Daemonize if requested
    if daemon_mode:
        daemonize()
        setup_logging(log_file=log_file, daemon_mode=True)

    mode_str = "passive" if not active_mode else "active"
    daemon_str = " (daemon)" if daemon_mode else ""

    logger.info(
        f"Starting LACP simulation on interfaces: {interfaces} in {mode_str} mode with {rate_mode} rate{daemon_str}"
    )

    actor = LacpActor(
        interfaces,
        rate_mode=rate_mode,
        active_mode=active_mode,
        inject_rules=inject_rules,
        exit_after_inject=exit_after_inject,
    )

    try:
        actor.start()

        # If exit_after_inject is enabled, wait for threads to complete
        if exit_after_inject:
            logger.info("Waiting for injection completion...")
            # Wait for all threads to complete
            for thread in actor.threads:
                thread.join()
            logger.info("All threads completed, exiting daemon")
        else:
            # Normal daemon mode - wait indefinitely
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        if not daemon_mode:
            logger.info("Shutting down LACP daemon...")
    finally:
        actor.stop()


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="LACP Active Simulator Daemon",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Main action group
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument(
        "-s",
        "--status",
        action="store_true",
        help="Query the status of the running LACP daemon",
    )
    group.add_argument(
        "-k",
        "--kill",
        action="store_true",
        help="Kill LACP daemon processes in the current or specified namespace",
    )

    # Interface argument (can be used with -s for filtering or standalone for daemon start)
    parser.add_argument(
        "-i",
        "--interface",
        action="append",
        dest="interfaces",
        help="Network interface to use (can be specified multiple times to start daemon or filter status)",
    )

    # Output format group
    output_format_group = parser.add_mutually_exclusive_group()
    output_format_group.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Output status in compact JSON format.\n(Only used with -s/--status)",
    )
    output_format_group.add_argument(
        "-p",
        "--pretty",
        action="store_true",
        help="Output status in pretty-printed JSON format.\n(Only used with -s/--status)",
    )

    # Optional arguments
    parser.add_argument(
        "-n",
        "--namespace",
        type=str,
        help="Filter status by network namespace name or specify namespace for kill operation",
    )

    parser.add_argument(
        "--rate",
        type=str,
        choices=[LACP_RATE_FAST, LACP_RATE_SLOW],
        default=LACP_RATE_FAST,
        help=f"LACP rate mode: {LACP_RATE_FAST} (1s interval, 3s timeout) or "
        f"{LACP_RATE_SLOW} (30s interval, 90s timeout)",
    )

    parser.add_argument(
        "--passive",
        action="store_true",
        help="Run in passive mode (only send LACPDUs when partner is active)",
    )

    parser.add_argument("-d", "--daemon", action="store_true", help="Run as daemon in background")

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Set logging level (default: INFO)",
    )

    parser.add_argument(
        "--log-file",
        type=str,
        help="Save log messages to the specified file",
    )

    parser.add_argument(
        "--inject",
        type=str,
        action="append",
        help=(
            "Inject state changes when conditions are met. "
            "Format: 'A:ATG|P:AT -> A:AT' or 'A:0x40|P:64 -> A:0x80'. "
            "Can be specified multiple times."
        ),
    )

    parser.add_argument(
        "--exit-after-inject",
        action="store_true",
        help="Exit the program after successfully injecting state changes and sending new LACPDUs",
    )

    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    """
    Validate command line arguments.

    Args:
        args: Parsed command line arguments

    Raises:
        SystemExit: If arguments are invalid
    """
    if args.kill:
        if args.json or args.pretty:
            raise SystemExit("Output format options cannot be used with -k/--kill.")
        # Check if daemon options were explicitly set (not just default values)
        if args.rate != LACP_RATE_FAST or args.passive or args.daemon:
            raise SystemExit("Daemon options cannot be used with -k/--kill.")

    elif args.status:
        # Check if daemon options were explicitly set (not just default values)
        if args.rate != LACP_RATE_FAST or args.passive or args.daemon:
            raise SystemExit("Daemon options cannot be used with -s/--status.")

    elif args.interfaces:
        if args.json or args.pretty or args.namespace:
            raise SystemExit("Output format and filtering options can only be used with -s/--status.")

    # Check if no action is specified
    if not args.status and not args.kill and not args.interfaces:
        raise SystemExit("Must specify either -s/--status, -k/--kill, or -i/--interface.")


def main() -> None:
    """Main entry point for the LACP daemon."""
    parser = create_argument_parser()
    args = parser.parse_args()

    # Setup logging
    setup_logging(level=getattr(logging, args.log_level), log_file=args.log_file)

    try:
        validate_arguments(args)
    except SystemExit as e:
        parser.error(str(e))

    try:
        if args.kill:
            kill_lacpd_processes(namespace=args.namespace)

        elif args.status:
            # Use -i interfaces as filter when querying status
            query_status(
                as_json=args.json,
                pretty=args.pretty,
                namespace=args.namespace,
                interfaces=args.interfaces,
            )

        elif args.interfaces:
            run_daemon(
                interfaces=args.interfaces,
                rate_mode=args.rate,
                active_mode=not args.passive,
                daemon_mode=args.daemon,
                log_file=args.log_file,
                inject_rules=args.inject,
                exit_after_inject=args.exit_after_inject,
            )

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
