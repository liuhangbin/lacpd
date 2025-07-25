"""
LACP Utility Functions

This module provides utility functions for network namespace handling,
Unix socket communication, process management, and logging setup.

Copyright (C) 2025 LACP Daemon Team
SPDX-License-Identifier: GPL-3.0-or-later
"""

import glob
import json
import logging
import os
import signal
import socket
import sys
import time
from typing import Any, cast

from lacpd.actor import get_netns_id

logger = logging.getLogger(__name__)


def get_ns_id_from_name(ns_name: str | None) -> str | None:
    """
    Get the namespace ID from its name.
    This is specific to Linux.

    Args:
        ns_name: Network namespace name

    Returns:
        Namespace ID string or None if not found
    """
    if not ns_name:
        return None

    # Try the new iproute2 mount-based approach first
    try:
        # New iproute2 uses mount to mount netns
        # The mount point is typically /var/run/netns/<ns_name>
        mount_path = f"/var/run/netns/{ns_name}"
        if os.path.exists(mount_path):
            # Get the inode number using os.stat
            stat_info = os.stat(mount_path)
            ns_inode = str(stat_info.st_ino)
            return f"net:[{ns_inode}]"
    except (OSError, AttributeError) as e:
        logger.debug(f"Mount-based namespace lookup failed for '{ns_name}': {e}")

    # Fallback to the old symlink-based approach
    try:
        return os.readlink(f"/var/run/netns/{ns_name}")
    except (OSError, AttributeError):
        logger.warning(f"Could not find network namespace '{ns_name}'.")
        return None


def get_socket_paths_for_namespace(namespace: str | None = None) -> list[str]:
    """
    Get socket paths for the specified namespace.
    Returns a list of socket paths that belong to the target namespace.

    Args:
        namespace: Network namespace name to filter by

    Returns:
        List of socket paths
    """
    # Determine the target namespace ID
    target_ns_id = get_ns_id_from_name(namespace) if namespace else get_netns_id()

    # Extract the inode number from the namespace ID for socket path matching
    if target_ns_id is not None:
        try:
            ns_inode = target_ns_id.split("[")[-1].rstrip("]")
            target_socket_pattern = f"/tmp/lacpd.ns{ns_inode}.sock"
        except (IndexError, AttributeError):
            # Fallback to PID-based pattern if namespace ID format is unexpected
            target_socket_pattern = "/tmp/lacpd.*.sock"
    else:
        # Fallback to PID-based pattern if namespace ID is not available
        logger.warning("Could not determine target namespace ID, using fallback pattern.")
        target_socket_pattern = "/tmp/lacpd.*.sock"

    # Get socket paths for the target namespace
    socket_paths = glob.glob(target_socket_pattern)
    return socket_paths


def get_daemon_status_from_socket(socket_path: str) -> dict[str, Any] | None:
    """
    Get daemon status from a socket path.
    Returns the daemon status dict or None if failed.

    Args:
        socket_path: Path to the Unix domain socket

    Returns:
        Daemon status dictionary or None if failed
    """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(socket_path)
        sock.sendall(b"status")

        response = b""
        while True:
            data = sock.recv(1024)
            if not data:
                break
            response += data

        daemon_status = cast(dict[str, Any], json.loads(response.decode("utf-8")))
        return daemon_status

    except OSError:
        # Socket may be stale, try to remove it
        try:
            os.remove(socket_path)
            logger.info(f"Removed stale socket: {socket_path}")
        except OSError:
            pass
        return None
    except json.JSONDecodeError:
        logger.error(f"Error decoding response from {socket_path}.")
        return None
    finally:
        sock.close()


def kill_lacpd_processes(namespace: str | None = None) -> bool:
    """
    Kill LACP daemon processes in the specified namespace and clean up socket files.

    Args:
        namespace: Network namespace name to target

    Returns:
        True if any processes were killed, False otherwise
    """
    socket_paths = get_socket_paths_for_namespace(namespace)

    if not socket_paths:
        ns_name = namespace if namespace else "current"
        logger.error(f"No LACP daemons found in namespace: {ns_name}")
        return False

    killed_count = 0
    cleaned_sockets = []

    for socket_path in socket_paths:
        daemon_status = get_daemon_status_from_socket(socket_path)
        if daemon_status is None:
            # Socket is stale, clean it up
            try:
                os.remove(socket_path)
                logger.info(f"Removed stale socket: {socket_path}")
                cleaned_sockets.append(socket_path)
            except OSError as e:
                logger.warning(f"Failed to remove stale socket {socket_path}: {e}")
            continue

        pid = daemon_status.get("pid")

        if pid and pid != "N/A":
            try:
                # Send SIGTERM to the process
                os.kill(pid, signal.SIGTERM)
                logger.info(f"Sent SIGTERM to LACP daemon PID {pid}")

                # Wait for the process to terminate and verify it's gone
                max_wait_time = 5.0  # Maximum wait time in seconds
                wait_interval = 0.1   # Check interval in seconds
                waited_time = 0.0

                while waited_time < max_wait_time:
                    try:
                        # Check if process still exists
                        os.kill(pid, 0)  # Signal 0 doesn't kill, just checks if process exists
                        time.sleep(wait_interval)
                        waited_time += wait_interval
                    except ProcessLookupError:
                        # Process has terminated
                        logger.info(f"Process {pid} has terminated")
                        killed_count += 1

                        # Now safe to remove the socket file
                        try:
                            os.remove(socket_path)
                            logger.info(f"Removed socket file: {socket_path}")
                            cleaned_sockets.append(socket_path)
                        except OSError as e:
                            logger.warning(f"Failed to remove socket {socket_path}: {e}")
                        break
                    except PermissionError:
                        # Process exists but we don't have permission to signal it
                        logger.warning(f"Process {pid} exists but permission denied to check status")
                        break
                else:
                    # Process didn't terminate within timeout
                    logger.warning(f"Process {pid} did not terminate within {max_wait_time} seconds")
                    # Don't remove socket file - process is still running

            except ProcessLookupError:
                logger.info(f"Process {pid} not found, may have already terminated")
                # Process is already gone, safe to remove socket file
                try:
                    os.remove(socket_path)
                    logger.info(f"Removed socket file for terminated process: {socket_path}")
                    cleaned_sockets.append(socket_path)
                except OSError as e:
                    logger.warning(f"Failed to remove socket {socket_path}: {e}")
            except PermissionError:
                logger.error(f"Permission denied to kill process {pid}")
                # Don't remove socket file - process is still running
            except Exception as e:
                logger.error(f"Error killing process {pid}: {e}")
                # Don't remove socket file - process may still be running

    if killed_count > 0 or cleaned_sockets:
        ns_name = namespace if namespace else "current"
        if killed_count > 0:
            logger.info(f"Successfully terminated {killed_count} LACP daemon(s) in namespace: {ns_name}")
        if cleaned_sockets:
            logger.info(f"Cleaned up {len(cleaned_sockets)} socket file(s) in namespace: {ns_name}")
        return True
    else:
        return False


def daemonize() -> None:
    """
    Daemonize the current process.

    This function forks the process twice and redirects standard file descriptors
    to /dev/null to create a proper daemon process.
    """
    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            # Parent process, exit
            os._exit(0)
    except OSError as err:
        logger.error(f"Fork #1 failed: {err}")
        os._exit(1)

    # Decouple from parent environment
    os.chdir("/")
    os.umask(0)
    os.setsid()

    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Parent process, exit
            os._exit(0)
    except OSError as err:
        logger.error(f"Fork #2 failed: {err}")
        os._exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()

    with open("/dev/null") as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open("/dev/null", "a+") as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
    with open("/dev/null", "a+") as f:
        os.dup2(f.fileno(), sys.stderr.fileno())


def setup_logging(
    level: str | int = logging.INFO,
    format_string: str | None = None,
    log_file: str | None = None,
) -> None:
    """
    Setup logging configuration.

    Args:
        level: Logging level (string or int)
        format_string: Custom format string for log messages
        log_file: Optional log file path
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper())

    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Create formatter
    formatter = logging.Formatter(format_string)

    # Create handlers
    handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    handlers.append(console_handler)

    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)  # type: ignore[arg-type]

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers and add new ones
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    for handler in handlers:
        root_logger.addHandler(handler)