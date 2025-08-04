"""
Unit tests for the utils module.

Tests utility functions for namespace management, socket operations,
and process management.

Copyright (C) 2025 LACP Daemon Team
SPDX-License-Identifier: GPL-3.0-or-later
"""

import json
from unittest.mock import Mock, mock_open, patch

from lacpd.utils import (
    daemonize,
    get_daemon_status_from_socket,
    get_ns_id_from_name,
    get_socket_paths_for_namespace,
    kill_lacpd_processes,
    setup_logging,
)


class TestNamespaceManagement:
    """Test namespace management functions."""

    @patch("os.path.exists")
    @patch("os.stat")
    @patch("os.readlink")
    def test_get_ns_id_from_name_success_mount_based(self, mock_readlink, mock_stat, mock_exists):
        """Test successful namespace ID retrieval using mount-based approach."""
        # Mock the mount-based approach
        mock_exists.return_value = True
        mock_stat_obj = Mock()
        mock_stat_obj.st_ino = 4026531992
        mock_stat.return_value = mock_stat_obj

        # Mock the fallback readlink (should not be called)
        mock_readlink.return_value = "net:[999999]"

        result = get_ns_id_from_name("test_ns")

        assert result == "net:[4026531992]"
        mock_stat.assert_called_once_with("/var/run/netns/test_ns")
        mock_readlink.assert_not_called()

    @patch("os.path.exists")
    @patch("os.stat")
    @patch("os.readlink")
    def test_get_ns_id_from_name_success_symlink_fallback(self, mock_readlink, mock_stat, mock_exists):
        """Test successful namespace ID retrieval using symlink fallback."""
        # Mock the mount-based approach to fail
        mock_exists.return_value = True
        mock_stat.side_effect = OSError("Permission denied")

        # Mock the fallback readlink
        mock_readlink.return_value = "net:[4026531992]"

        result = get_ns_id_from_name("test_ns")

        assert result == "net:[4026531992]"
        mock_readlink.assert_called_once_with("/var/run/netns/test_ns")

    @patch("os.readlink")
    def test_get_ns_id_from_name_success(self, mock_readlink):
        """Test successful namespace ID retrieval (legacy test)."""
        mock_readlink.return_value = "net:[4026531992]"

        result = get_ns_id_from_name("test_ns")

        assert result == "net:[4026531992]"
        mock_readlink.assert_called_once_with("/var/run/netns/test_ns")

    @patch("os.path.exists")
    @patch("os.readlink")
    def test_get_ns_id_from_name_not_found(self, mock_readlink, mock_exists):
        """Test namespace ID retrieval when namespace doesn't exist."""
        # Mock the mount-based approach to fail (file doesn't exist)
        mock_exists.return_value = False

        # Mock the fallback readlink to also fail
        mock_readlink.side_effect = OSError("No such file or directory")

        result = get_ns_id_from_name("nonexistent_ns")

        assert result is None

    def test_get_ns_id_from_name_none(self):
        """Test namespace ID retrieval with None input."""
        result = get_ns_id_from_name(None)
        assert result is None

    @patch("lacpd.utils.get_ns_id_from_name")
    @patch("lacpd.utils.get_netns_id")
    @patch("glob.glob")
    def test_get_socket_paths_for_namespace_with_namespace(
        self, mock_glob, mock_get_netns_id, mock_get_ns_id_from_name
    ):
        """Test socket path retrieval with specific namespace."""
        mock_get_ns_id_from_name.return_value = "net:[4026531992]"
        mock_glob.return_value = ["/tmp/lacpd.ns4026531992.sock"]

        result = get_socket_paths_for_namespace("test_ns")

        assert result == ["/tmp/lacpd.ns4026531992.sock"]
        mock_get_ns_id_from_name.assert_called_once_with("test_ns")
        mock_glob.assert_called_once_with("/tmp/lacpd.ns4026531992.sock")

    @patch("lacpd.utils.get_netns_id")
    @patch("glob.glob")
    def test_get_socket_paths_for_namespace_current(self, mock_glob, mock_get_netns_id):
        """Test socket path retrieval for current namespace."""
        mock_get_netns_id.return_value = "net:[4026531992]"
        mock_glob.return_value = ["/tmp/lacpd.ns4026531992.sock"]

        result = get_socket_paths_for_namespace()

        assert result == ["/tmp/lacpd.ns4026531992.sock"]
        mock_get_netns_id.assert_called_once()

    @patch("lacpd.utils.get_netns_id")
    @patch("glob.glob")
    def test_get_socket_paths_for_namespace_fallback(self, mock_glob, mock_get_netns_id):
        """Test socket path retrieval with fallback pattern."""
        mock_get_netns_id.return_value = None
        mock_glob.return_value = ["/tmp/lacpd.123.sock"]

        result = get_socket_paths_for_namespace()

        assert result == ["/tmp/lacpd.123.sock"]
        mock_glob.assert_called_once_with("/tmp/lacpd.*.sock")


class TestSocketOperations:
    """Test socket operation functions."""

    @patch("socket.socket")
    def test_get_daemon_status_from_socket_success(self, mock_socket_class):
        """Test successful daemon status retrieval."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        status_data = {"pid": 12345, "ports": []}
        mock_socket.recv.side_effect = [
            json.dumps(status_data).encode("utf-8"),
            b"",  # Empty response to end loop
        ]

        result = get_daemon_status_from_socket("/tmp/test.sock")

        assert result == status_data
        mock_socket.connect.assert_called_once_with("/tmp/test.sock")
        mock_socket.sendall.assert_called_once_with(b"status")
        mock_socket.close.assert_called_once()

    @patch("socket.socket")
    @patch("os.remove")
    def test_get_daemon_status_from_socket_error(self, mock_remove, mock_socket_class):
        """Test daemon status retrieval with socket error."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        mock_socket.connect.side_effect = OSError("Connection refused")

        result = get_daemon_status_from_socket("/tmp/test.sock")

        assert result is None
        mock_remove.assert_called_once_with("/tmp/test.sock")
        mock_socket.close.assert_called_once()

    @patch("socket.socket")
    def test_get_daemon_status_from_socket_json_error(self, mock_socket_class):
        """Test daemon status retrieval with JSON decode error."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        mock_socket.recv.side_effect = [b"invalid json", b""]

        result = get_daemon_status_from_socket("/tmp/test.sock")

        assert result is None
        mock_socket.close.assert_called_once()


class TestProcessManagement:
    """Test process management functions."""

    @patch("lacpd.utils.get_socket_paths_for_namespace")
    @patch("lacpd.utils.get_daemon_status_from_socket")
    @patch("os.kill")
    @patch("os.remove")
    def test_kill_lacpd_processes_success(self, mock_remove, mock_kill, mock_get_status, mock_get_paths):
        """Test successful process termination."""
        mock_get_paths.return_value = ["/tmp/lacpd.sock"]
        mock_get_status.return_value = {"pid": 12345}

        # Mock process termination sequence: SIGTERM succeeds, then process terminates
        mock_kill.side_effect = [
            None,  # SIGTERM sent successfully
            ProcessLookupError("No such process"),  # Process terminated
        ]
        mock_remove.return_value = None

        result = kill_lacpd_processes()

        assert result is True
        # Should have called kill twice: SIGTERM + check
        assert mock_kill.call_count == 2
        mock_kill.assert_any_call(12345, 15)  # SIGTERM
        mock_kill.assert_any_call(12345, 0)  # Check if process exists
        # Should have removed socket after process terminated
        mock_remove.assert_called_once_with("/tmp/lacpd.sock")

    @patch("lacpd.utils.get_socket_paths_for_namespace")
    def test_kill_lacpd_processes_no_sockets(self, mock_get_paths):
        """Test process termination when no sockets found."""
        mock_get_paths.return_value = []

        result = kill_lacpd_processes()

        assert result is False

    @patch("lacpd.utils.get_socket_paths_for_namespace")
    @patch("lacpd.utils.get_daemon_status_from_socket")
    @patch("os.kill")
    def test_kill_lacpd_processes_process_not_found(self, mock_kill, mock_get_status, mock_get_paths):
        """Test process termination when process not found."""
        mock_get_paths.return_value = ["/tmp/lacpd.sock"]
        mock_get_status.return_value = {"pid": 12345}
        mock_kill.side_effect = ProcessLookupError("No such process")

        result = kill_lacpd_processes()

        assert result is False


class TestDaemonization:
    """Test daemonization function."""

    @patch("os.fork")
    @patch("os.chdir")
    @patch("os.umask")
    @patch("os.setsid")
    @patch("builtins.open", new_callable=mock_open)
    @patch("os.dup2")
    @patch("os._exit")
    @patch("sys.stdin")
    @patch("sys.stdout")
    @patch("sys.stderr")
    def test_daemonize_success(
        self,
        mock_stderr,
        mock_stdout,
        mock_stdin,
        mock_exit,
        mock_dup2,
        mock_file,
        mock_setsid,
        mock_umask,
        mock_chdir,
        mock_fork,
    ):
        """Test successful daemonization."""
        # Mock file descriptors
        mock_stdin.fileno.return_value = 0
        mock_stdout.fileno.return_value = 1
        mock_stderr.fileno.return_value = 2

        mock_fork.side_effect = [
            1,
            0,
        ]  # First fork returns parent PID, second returns 0

        daemonize()

        assert mock_fork.call_count == 2
        mock_chdir.assert_called_once_with("/")
        mock_umask.assert_called_once_with(0)
        mock_setsid.assert_called_once()
        # Verify that os._exit was called once (for the first parent process)
        assert mock_exit.call_count == 1
        mock_exit.assert_called_once_with(0)

    @patch("os.fork")
    @patch("os._exit")
    @patch("sys.stdin")
    @patch("sys.stdout")
    @patch("sys.stderr")
    def test_daemonize_fork_error(self, mock_stderr, mock_stdout, mock_stdin, mock_exit, mock_fork):
        """Test daemonization with fork error."""
        # Mock file descriptors
        mock_stdin.fileno.return_value = 0
        mock_stdout.fileno.return_value = 1
        mock_stderr.fileno.return_value = 2

        mock_fork.side_effect = OSError("Fork failed")

        daemonize()

        # Verify that os._exit was called with error code 1 (called twice due to both forks failing)
        assert mock_exit.call_count == 2
        mock_exit.assert_any_call(1)


class TestLogging:
    """Test logging setup function."""

    @patch("logging.Formatter")
    @patch("logging.StreamHandler")
    @patch("logging.getLogger")
    def test_setup_logging_default(self, mock_get_logger, mock_stream_handler, mock_formatter):
        """Test logging setup with default parameters."""
        mock_logger = Mock()
        mock_logger.handlers = []  # Initialize handlers list
        mock_get_logger.return_value = mock_logger
        mock_handler = Mock()
        mock_stream_handler.return_value = mock_handler

        setup_logging()

        mock_formatter.assert_called_once()
        mock_stream_handler.assert_called_once()
        mock_logger.setLevel.assert_called_once()
        assert mock_logger.addHandler.call_count >= 1

    @patch("logging.Formatter")
    @patch("logging.StreamHandler")
    @patch("logging.FileHandler")
    @patch("logging.getLogger")
    def test_setup_logging_with_file(self, mock_get_logger, mock_file_handler, mock_stream_handler, mock_formatter):
        """Test logging setup with file handler."""
        mock_logger = Mock()
        mock_logger.handlers = []  # Initialize handlers list
        mock_get_logger.return_value = mock_logger
        mock_handler = Mock()
        mock_stream_handler.return_value = mock_handler
        mock_file_handler.return_value = mock_handler

        setup_logging(log_file="/tmp/test.log")

        mock_file_handler.assert_called_once_with("/tmp/test.log")
        assert mock_logger.addHandler.call_count >= 2
