"""
LACP Actor Implementation

This module implements the LACP Actor class and related functionality
for managing LACP state machines and packet processing.

Copyright (C) 2025 LACP Daemon Team
SPDX-License-Identifier: GPL-3.0-or-later
"""

import json
import logging
import os
import socket
import struct
import threading
import time

from lacpd.packet import build_ethernet_frame, build_lacpdu, parse_lacpdu

# Configure logging
logger = logging.getLogger(__name__)


def format_state_string(state: int) -> str:
    """
    Format LACP state bits into a compact string representation.

    Args:
        state: LACP state bits

    Returns:
        Compact state string (e.g., "ATG" for ACTIVE|AGGREGATION|SYNC)
    """
    bits = []
    if state & LACP_STATE_ACTIVE:
        bits.append("A")
    if state & LACP_STATE_SHORT_TIMEOUT:
        bits.append("T")
    if state & LACP_STATE_AGGREGATION:
        bits.append("G")
    if state & LACP_STATE_SYNC:
        bits.append("S")
    if state & LACP_STATE_COLLECTING:
        bits.append("C")
    if state & LACP_STATE_DISTRIBUTING:
        bits.append("D")
    if state & LACP_STATE_DEFAULTED:
        bits.append("F")
    if state & LACP_STATE_EXPIRED:
        bits.append("E")
    return "".join(bits) if bits else "N"


def parse_state_string(state_str: str) -> int:
    """
    Parse state string into LACP state bits.

    Args:
        state_str: State string (e.g., "ATG", "0x40", "64")

    Returns:
        LACP state bits as integer
    """
    state_str = state_str.strip().upper()

    # Handle hex format
    if state_str.startswith("0X"):
        return int(state_str, 16)

    # Handle decimal format
    if state_str.isdigit():
        return int(state_str)

    # Handle bit string format
    state = 0
    valid_chars = set("ATGSEFCD")
    for char in state_str:
        if char not in valid_chars:
            raise ValueError(f"Invalid state character: {char}")
        if char == "A":
            state |= LACP_STATE_ACTIVE
        elif char == "T":
            state |= LACP_STATE_SHORT_TIMEOUT
        elif char == "G":
            state |= LACP_STATE_AGGREGATION
        elif char == "S":
            state |= LACP_STATE_SYNC
        elif char == "E":
            state |= LACP_STATE_EXPIRED
        elif char == "C":
            state |= LACP_STATE_COLLECTING
        elif char == "D":
            state |= LACP_STATE_DISTRIBUTING
        elif char == "F":
            state |= LACP_STATE_DEFAULTED

    return state


def parse_inject_rule(inject_str: str) -> tuple[dict[str, int], dict[str, int]]:
    """
    Parse inject rule string into condition and target states.

    Args:
        inject_str: Inject rule string (e.g., "A:ATG|P:AT -> A:AT")

    Returns:
        Tuple of (condition_states, target_states)
        condition_states: dict with 'A' and/or 'P' keys
        target_states: dict with 'A' and/or 'P' keys
    """
    # Split on "->" (with optional spaces)
    parts = inject_str.split("->")
    if len(parts) != 2:
        raise ValueError(f"Invalid inject rule format: {inject_str}")

    condition_part = parts[0].strip()
    target_part = parts[1].strip()

    def parse_state_part(part: str) -> dict[str, int]:
        states: dict[str, int] = {}
        if not part:
            return states

        # Split on "|" (with optional spaces)
        state_parts = [p.strip() for p in part.split("|")]

        for state_part in state_parts:
            if ":" not in state_part:
                raise ValueError(f"Invalid state format: {state_part}")

            role, state_str = state_part.split(":", 1)
            role = role.strip().upper()
            if role not in ["A", "P"]:
                raise ValueError(f"Invalid role: {role}, must be 'A' or 'P'")

            parsed_state = parse_state_string(state_str.strip())
            # Validate that the state string was not empty and produced a valid state
            if not state_str.strip():
                raise ValueError(f"Invalid state format: {state_part}")
            states[role] = parsed_state

        return states

    condition_states = parse_state_part(condition_part)
    target_states = parse_state_part(target_part)

    # Require at least one target state
    if not target_states:
        raise ValueError(f"Invalid inject rule format: {inject_str}")

    return condition_states, target_states


# LACP state bits
LACP_STATE_ACTIVE = 0b00000001
LACP_STATE_SHORT_TIMEOUT = 0b00000010
LACP_STATE_AGGREGATION = 0b00000100
LACP_STATE_SYNC = 0b00001000
LACP_STATE_COLLECTING = 0b00010000
LACP_STATE_DISTRIBUTING = 0b00100000
LACP_STATE_DEFAULTED = 0b01000000
LACP_STATE_EXPIRED = 0b10000000

# LACP rate modes
LACP_RATE_FAST = "fast"
LACP_RATE_SLOW = "slow"

# LACP timing constants
LACP_TIMING = {
    LACP_RATE_FAST: {"tx_interval": 1, "timeout": 3},  # 1 second  # 3 seconds
    LACP_RATE_SLOW: {"tx_interval": 30, "timeout": 90},  # 30 seconds  # 90 seconds
}


def get_netns_id() -> str | None:
    """
    Get the inode of the network namespace for the current process.
    This is specific to Linux.

    Returns:
        Namespace ID string or None if not available
    """
    try:
        return os.readlink("/proc/self/ns/net")
    except (OSError, AttributeError):
        # Fallback: try to get the inode directly from /proc/self/ns/net
        try:
            stat_info = os.stat("/proc/self/ns/net")
            ns_inode = str(stat_info.st_ino)
            return f"net:[{ns_inode}]"
        except (OSError, AttributeError):
            return None


def get_mac_address(ifname: str) -> str:
    """
    Get the MAC address of a network interface.

    Args:
        ifname: Interface name

    Returns:
        MAC address as colon-separated hex string

    Raises:
        OSError: If interface information cannot be retrieved
    """
    import fcntl

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack("256s", ifname[:15].encode("utf-8")))
        return ":".join(f"{b:02x}" for b in info[18:24])
    finally:
        sock.close()


class Port:
    """
    Represents a single LACP port with its state machine and partner information.

    This class manages the LACP state machine for a single network interface,
    including partner detection, state transitions, and LACPDU transmission logic.
    """

    def __init__(
        self,
        iface_name: str,
        port_id: int,
        system_id: str,
        key: int,
        rate_mode: str = LACP_RATE_FAST,
        active_mode: bool = True,
        inject_rules: list[str] | None = None,
        actor_ref: "LacpActor | None" = None,
    ) -> None:
        """
        Initialize a new LACP port.

        Args:
            iface_name: Network interface name
            port_id: Unique port identifier
            system_id: System MAC address
            key: LACP aggregation key
            rate_mode: LACP rate mode ('fast' or 'slow')
            active_mode: Whether to run in active mode
        """
        self.iface = iface_name
        self.last_rx_time = 0.0
        self.lock = threading.RLock()
        self.rate_mode = rate_mode
        self.timing = LACP_TIMING[rate_mode]
        self.active_mode = active_mode
        self.partner_active = False  # Track if partner is active
        self.should_send = active_mode  # Whether we should send LACPDUs

        self.mux_state = "DETACHED"
        self.selected = False

        # State tracking for logging
        self.last_actor_state = 0
        self.last_partner_state = 0

        # Actor information (our side)
        # Initialize state based on rate_mode and active_mode
        actor_state = LACP_STATE_AGGREGATION  # Always set aggregation bit

        if active_mode:
            actor_state |= LACP_STATE_ACTIVE

        if rate_mode == LACP_RATE_FAST:
            actor_state |= LACP_STATE_SHORT_TIMEOUT

        self.actor_info: dict[str, int | str] = {
            "system_priority": 32768,
            "system": system_id,
            "key": key,
            "port_priority": 32768,
            "port": port_id,
            "state": actor_state,
        }

        # Default partner information
        self.partner_info_default: dict[str, int | str] = {
            "system_priority": 0,
            "system": "00:00:00:00:00:00",
            "key": 0,
            "port_priority": 0,
            "port": 0,
            "state": LACP_STATE_DEFAULTED,
        }
        self.partner_info: dict[str, int | str] = self.partner_info_default.copy()

        # Initialize state tracking
        self.last_actor_state = actor_state
        self.last_partner_state = LACP_STATE_DEFAULTED

        # Initialize inject rules
        self.inject_rules = inject_rules or []
        self.parsed_rules = []
        self.actor_ref = actor_ref
        self.inject_completed = False
        if inject_rules:
            for rule in inject_rules:
                try:
                    condition_states, target_states = parse_inject_rule(rule)
                    self.parsed_rules.append((condition_states, target_states))
                    logger.info(f"Inject rule configured for {self.iface}: {rule}")
                except ValueError as e:
                    logger.error(f"Invalid inject rule '{rule}': {e}")

    def _log_state_change(self) -> None:
        """
        Log state changes in the format: "eth0 state changed: A:ATG|P:A -> A:ATG|P:AT"
        """
        current_actor_state = int(self.actor_info["state"])
        current_partner_state = int(self.partner_info["state"])

        # Only log if there's a change
        if current_actor_state != self.last_actor_state or current_partner_state != self.last_partner_state:
            old_actor_str = format_state_string(self.last_actor_state)
            old_partner_str = format_state_string(self.last_partner_state)
            new_actor_str = format_state_string(current_actor_state)
            new_partner_str = format_state_string(current_partner_state)

            logger.info(
                f"{self.iface} state changed: "
                f"A:{old_actor_str}|P:{old_partner_str} -> "
                f"A:{new_actor_str}|P:{new_partner_str}"
            )

            # Update last states
            self.last_actor_state = current_actor_state
            self.last_partner_state = current_partner_state

    def _check_inject_rules(self) -> None:
        """
        Check if inject conditions are met and apply target states.
        """
        if not self.parsed_rules:
            return

        current_actor_state = int(self.actor_info["state"])
        current_partner_state = int(self.partner_info["state"])

        # Check each rule
        for condition_states, target_states in self.parsed_rules:
            # Check if all conditions are met
            conditions_met = True
            for role, expected_state in condition_states.items():
                if role == "A":
                    if current_actor_state != expected_state:
                        conditions_met = False
                        break
                elif role == "P":
                    if current_partner_state != expected_state:
                        conditions_met = False
                        break

            if conditions_met:
                # Apply target states
                inject_applied = False
                for role, target_state in target_states.items():
                    if role == "A":
                        old_state = current_actor_state
                        self.actor_info["state"] = target_state
                        logger.info(
                            f"Inject rule triggered on {self.iface}: "
                            f"Actor state {format_state_string(old_state)} -> {format_state_string(target_state)}"
                        )
                        inject_applied = True
                    elif role == "P":
                        old_state = current_partner_state
                        self.partner_info["state"] = target_state
                        logger.info(
                            f"Inject rule triggered on {self.iface}: "
                            f"Partner state {format_state_string(old_state)} -> {format_state_string(target_state)}"
                        )
                        inject_applied = True

                # Notify actor if injection was applied
                if inject_applied and self.actor_ref:
                    self.actor_ref.inject_triggered = True

    def update_partner(self, partner_info: dict | None) -> None:
        """
        Update partner information from received LACPDU.

        Args:
            partner_info: Partner information from LACPDU actor TLV (sender's info)
        """
        with self.lock:
            if partner_info:
                # Update partner info from LACPDU actor TLV (sender's info)
                self.partner_info = {k: (int(v) if k != "system" else str(v)) for k, v in partner_info.items()}
                self.last_rx_time = time.time()

                # Check if partner is active
                partner_state = int(self.partner_info["state"])
                partner_is_active = bool(partner_state & LACP_STATE_ACTIVE)
                self.partner_active = partner_is_active

                # Update should_send logic for passive mode
                if not self.active_mode:
                    # In passive mode, only send if partner is active
                    self.should_send = partner_is_active

                # Log partner state for debugging
                partner_state_str = format_state_string(partner_state)
                logger.debug(f"Received LACPDU from partner on {self.iface}, partner state: {partner_state_str}")

                # Log state change
                self._log_state_change()
            else:
                # Clear partner information when None is passed
                self.partner_info = self.partner_info_default.copy()
                self.partner_active = False
                self.last_rx_time = 0.0

                # In passive mode, stop sending if partner is cleared
                if not self.active_mode:
                    self.should_send = False

                logger.debug(f"Cleared partner information on {self.iface}")

                # Log state change
                self._log_state_change()

    def _run_selection_logic(self, lacpdu_info: dict | None = None) -> None:
        """
        Run the LACP selection logic to determine if port is selected.

        According to IEEE 802.3ad standard:
        - Actor selection: compare our actor info with received partner TLV (sender's view of our actor info)
        - Also check if partner is individual link (Actor_State.Aggregation = 0)

        Args:
            lacpdu_info: Complete LACPDU information containing both actor and partner TLVs
        """
        partner_state = int(self.partner_info["state"])

        # Actor selection: compare our actor info with received partner TLV
        if lacpdu_info and "actor" in lacpdu_info and "partner" in lacpdu_info:
            actor_tlv = lacpdu_info["actor"]  # Sender's info (our partner info)
            partner_tlv = lacpdu_info["partner"]  # Sender's view of our actor info

            # Check if partner is individual link (Actor_State.Aggregation = 0)
            actor_state = int(actor_tlv["state"])
            partner_is_individual = not bool(actor_state & LACP_STATE_AGGREGATION)

            if partner_is_individual:
                # If partner is individual link, we should be selected
                self.selected = True
                logger.debug(
                    f"Actor selection on {self.iface}: "
                    f"partner is individual link (Actor_State.Aggregation=0), selected=True"
                )
            else:
                # Compare all required fields according to IEEE 802.3ad standard
                fields_match = (
                    int(self.actor_info["port"]) == int(partner_tlv["port"])
                    and int(self.actor_info["port_priority"]) == int(partner_tlv["port_priority"])
                    and str(self.actor_info["system"]) == str(partner_tlv["system"])
                    and int(self.actor_info["system_priority"]) == int(partner_tlv["system_priority"])
                    and int(self.actor_info["key"]) == int(partner_tlv["key"])
                    and bool(int(self.actor_info["state"]) & LACP_STATE_AGGREGATION)
                    == bool(int(partner_tlv["state"]) & LACP_STATE_AGGREGATION)
                )

                # Build debug message in parts to avoid long lines
                port_match = int(self.actor_info["port"]) == int(partner_tlv["port"])
                port_priority_match = int(self.actor_info["port_priority"]) == int(partner_tlv["port_priority"])
                system_match = str(self.actor_info["system"]) == str(partner_tlv["system"])
                system_priority_match = int(self.actor_info["system_priority"]) == int(partner_tlv["system_priority"])
                key_match = int(self.actor_info["key"]) == int(partner_tlv["key"])
                aggregation_match = bool(int(self.actor_info["state"]) & LACP_STATE_AGGREGATION) == bool(
                    int(partner_tlv["state"]) & LACP_STATE_AGGREGATION
                )

                logger.debug(
                    f"Actor selection on {self.iface}: "
                    f"port_match={port_match}, "
                    f"port_priority_match={port_priority_match}, "
                    f"system_match={system_match}, "
                    f"system_priority_match={system_priority_match}, "
                    f"key_match={key_match}, "
                    f"aggregation_match={aggregation_match}, "
                    f"fields_match={fields_match}"
                )

                partner_not_expired = not (partner_state & LACP_STATE_EXPIRED)
                self.selected = fields_match and partner_not_expired

                if not self.selected:
                    logger.debug(
                        f"Selection failed on {self.iface}: "
                        f"fields_match={fields_match}, "
                        f"partner_not_expired={partner_not_expired} "
                        f"(partner_state={format_state_string(partner_state)})"
                    )
        else:
            # No LACPDU info received, cannot perform selection
            self.selected = False
            logger.debug(
                f"Actor selection on {self.iface}: "
                f"no LACPDU info received, selected=False"
            )

    def _run_mux_machine(self) -> None:
        """Run the LACP Mux state machine."""
        partner_state = int(self.partner_info["state"])
        partner_is_in_sync = bool(partner_state & LACP_STATE_SYNC)

        # 1. Update actor's SYNC bit based on selection
        if self.selected:
            self.actor_info["state"] = int(self.actor_info["state"]) | LACP_STATE_SYNC
        else:
            self.actor_info["state"] = int(self.actor_info["state"]) & ~LACP_STATE_SYNC

        # 2. Mux state transitions
        old_mux_state = self.mux_state
        if self.mux_state == "DETACHED":
            if self.selected:
                self.mux_state = "ATTACHED"
        elif self.mux_state == "ATTACHED":
            if not self.selected:
                self.mux_state = "DETACHED"
            elif partner_is_in_sync:
                self.mux_state = "COLLECTING_DISTRIBUTING"
        elif self.mux_state == "COLLECTING_DISTRIBUTING":
            if not self.selected or not partner_is_in_sync:
                self.mux_state = "ATTACHED"

        # Debug logging for mux state transitions
        if old_mux_state != self.mux_state:
            logger.debug(
                f"Mux state transition on {self.iface}: "
                f"{old_mux_state} -> {self.mux_state} "
                f"(selected={self.selected}, partner_is_in_sync={partner_is_in_sync})"
            )

        # 3. Update actor's state based on Mux state
        if self.mux_state == "COLLECTING_DISTRIBUTING":
            self.actor_info["state"] = int(self.actor_info["state"]) | (LACP_STATE_COLLECTING | LACP_STATE_DISTRIBUTING)
        else:
            self.actor_info["state"] = int(self.actor_info["state"]) & ~(
                LACP_STATE_COLLECTING | LACP_STATE_DISTRIBUTING
            )

    def update_state(self) -> None:
        """Update port state based on timeouts and run state machines."""
        with self.lock:
            # 1. Timeout Check - use rate-specific timeout
            if self.last_rx_time and (time.time() - self.last_rx_time > self.timing["timeout"]):
                self.partner_info = self.partner_info_default.copy()
                self.partner_info["state"] = int(self.partner_info["state"]) | LACP_STATE_EXPIRED
                self.partner_active = False

                # In passive mode, stop sending if partner times out
                if not self.active_mode:
                    self.should_send = False
            else:
                if self.partner_info:  # Ensure partner_info is not None
                    self.partner_info["state"] = int(self.partner_info["state"]) & ~LACP_STATE_EXPIRED

            # 2. Run state machines (selection logic is now called in update_partner)
            self._run_mux_machine()

            # 3. Check and apply inject rules
            self._check_inject_rules()

            # 4. Log state changes
            self._log_state_change()

    def get_current_tx_interval(self) -> int:
        """
        Get the current transmission interval based on partner's timeout setting.
        """
        with self.lock:
            # If partner has SHORT_TIMEOUT bit set, use fast mode
            if self.partner_info and (int(self.partner_info["state"]) & LACP_STATE_SHORT_TIMEOUT):
                return LACP_TIMING[LACP_RATE_FAST]["tx_interval"]
            else:
                # Default to slow mode if partner doesn't have SHORT_TIMEOUT or no partner
                return LACP_TIMING[LACP_RATE_SLOW]["tx_interval"]

    def should_send_lacpdu(self) -> bool:
        """
        Determine if we should send LACPDU based on active/passive mode and partner state.

        Returns:
            True if LACPDU should be sent, False otherwise
        """
        with self.lock:
            return self.should_send

    def get_status(self) -> dict:
        """
        Get current port status information.
        """
        with self.lock:
            # Determine current effective rate mode based on partner's timeout
            partner_state = int(self.partner_info["state"])
            current_rate = (
                LACP_RATE_FAST if (self.partner_info and partner_state & LACP_STATE_SHORT_TIMEOUT) else LACP_RATE_SLOW
            )

            return {
                "interface": self.iface,
                "configured_rate_mode": self.rate_mode,
                "effective_rate_mode": current_rate,
                "active_mode": self.active_mode,
                "partner_active": self.partner_active,
                "should_send": self.should_send,
                "mux_state": self.mux_state,
                "selected": self.selected,
                "actor": self.actor_info.copy(),
                "partner": self.partner_info.copy(),
            }


class LacpActor:
    """
    Main LACP actor that manages multiple ports and provides daemon functionality.

    This class coordinates multiple LACP ports, handles IPC communication,
    and manages the overall daemon lifecycle.
    """

    def __init__(
        self,
        interfaces: list[str],
        rate_mode: str = LACP_RATE_FAST,
        active_mode: bool = True,
        inject_rules: list[str] | None = None,
        exit_after_inject: bool = False,
    ) -> None:
        """
        Initialize a new LACP actor.

        Args:
            interfaces: List of network interface names
            rate_mode: LACP rate mode ('fast' or 'slow')
            active_mode: Whether to run in active mode
        """
        self.net_ns_id = get_netns_id()

        # Use namespace ID in socket path for more efficient filtering
        if self.net_ns_id:
            # Extract the inode number from the namespace ID
            try:
                ns_inode = self.net_ns_id.split("[")[-1].rstrip("]")
                self.socket_path = f"/tmp/lacpd.ns{ns_inode}.sock"
            except (IndexError, AttributeError):
                # Fallback to PID if namespace ID format is unexpected
                self.socket_path = f"/tmp/lacpd.{os.getpid()}.sock"
        else:
            # Fallback to PID if namespace ID is not available
            self.socket_path = f"/tmp/lacpd.{os.getpid()}.sock"

        self.interfaces_names = interfaces
        self.rate_mode = rate_mode
        self.active_mode = active_mode
        self.sockets: dict[str, socket.socket] = {}
        self.threads: list[threading.Thread] = []
        self.running = False
        self.exit_after_inject = exit_after_inject
        self.inject_triggered = False

        # Create ports for each interface
        system_id = get_mac_address(interfaces[0])
        self.ports = [
            Port(
                iface,
                i + 1,
                system_id,
                key=1,
                rate_mode=rate_mode,
                active_mode=active_mode,
                inject_rules=inject_rules,
                actor_ref=self,
            )
            for i, iface in enumerate(interfaces)
        ]

    def _send_lacpdu(self, port_obj: Port) -> None:
        """
        Send LACPDUs for a specific port.

        Args:
            port_obj: Port object to send LACPDUs for
        """
        sock = self.sockets[port_obj.iface]
        # The source MAC is the port's specific MAC, but the LACP System ID is shared
        src_mac = get_mac_address(port_obj.iface)
        dest_mac = "01:80:c2:00:00:02"

        last_send_time = 0.0

        while self.running:
            # Check if this port has completed injection
            if port_obj.inject_completed:
                logger.info(f"Port {port_obj.iface} injection completed, stopping LACPDU transmission")
                break

            current_time = time.time()

            # Check if we should send LACPDU based on active/passive mode
            if port_obj.should_send_lacpdu():
                # Get current transmission interval based on partner's timeout setting
                tx_interval = port_obj.get_current_tx_interval()

                # Check if it's time to send (based on last send time and current interval)
                if current_time - last_send_time >= tx_interval:
                    with port_obj.lock:
                        lacpdu_payload = build_lacpdu(port_obj.actor_info, port_obj.partner_info)

                    frame = build_ethernet_frame(dest_mac, src_mac, lacpdu_payload)

                    try:
                        sock.send(frame)
                        last_send_time = current_time
                        logger.debug(f"Sent LACPDU on {port_obj.iface} with interval {tx_interval}s")

                        # Check if we should exit after injection
                        if self.exit_after_inject and self.inject_triggered:
                            logger.info(
                                f"Exiting after successful injection and LACPDU transmission on {port_obj.iface}"
                            )
                            # Set flag to stop this specific port's threads
                            port_obj.inject_completed = True
                            # Exit this thread only
                            return
                    except Exception as e:
                        logger.error(f"Error sending on {port_obj.iface}: {e}")

            # Use shorter sleep interval to be more responsive to partner changes
            # This allows us to quickly adapt when partner switches between fast/slow modes
            time.sleep(0.1)  # 100ms sleep instead of full tx_interval

    def _listen_lacpdu(self, port_obj: Port) -> None:
        """
        Listen for LACPDUs on a specific port.

        Args:
            port_obj: Port object to listen on
        """
        sock = self.sockets[port_obj.iface]

        while self.running:
            # Check if this port has completed injection
            if port_obj.inject_completed:
                logger.info(f"Port {port_obj.iface} injection completed, stopping LACPDU listening")
                break

            try:
                sock.settimeout(1.0)
                packet = sock.recv(2048)
            except TimeoutError:
                continue

            eth_header = packet[:14]
            eth_type = struct.unpack("!6s6sH", eth_header)[2]

            if eth_type == 0x8809:
                lacpdu_payload = packet[14:]
                lacpdu_info = parse_lacpdu(lacpdu_payload)
                if lacpdu_info:
                    port_obj.update_partner(lacpdu_info["actor"])
                    port_obj._run_selection_logic(lacpdu_info)

    def _state_machine_updater(self) -> None:
        """Update state machines for all ports periodically."""
        while self.running:
            # Check if all ports have completed injection
            all_ports_completed = all(port.inject_completed for port in self.ports)
            if all_ports_completed and self.exit_after_inject:
                logger.info("All ports have completed injection, stopping state machine updater")
                # Set running to False to signal other threads to exit
                self.running = False
                break

            for port in self.ports:
                if not port.inject_completed:
                    port.update_state()
            time.sleep(1)

    def _run_ipc_server(self) -> None:
        """Run the IPC server for status queries."""
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_sock.bind(self.socket_path)
        server_sock.listen(1)
        server_sock.settimeout(1.0)

        logger.info(f"IPC server listening on {self.socket_path}")

        while self.running:
            try:
                client_sock, _ = server_sock.accept()
                with client_sock:
                    command = client_sock.recv(1024)
                    if command == b"status":
                        port_statuses = [port.get_status() for port in self.ports]
                        status_data = {
                            "pid": os.getpid(),
                            "net_ns_id": self.net_ns_id,
                            "configured_rate_mode": self.rate_mode,
                            "active_mode": self.active_mode,
                            "ports": port_statuses,
                        }
                        response = json.dumps(status_data, indent=4).encode("utf-8")
                        client_sock.sendall(response)
            except TimeoutError:
                continue
            except Exception as e:
                logger.error(f"IPC Server Error: {e}")

        logger.info("IPC server stopped")

        server_sock.close()
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

    def start(self) -> None:
        """Start the LACP actor and all associated threads."""
        self.running = True
        mode_str = "active" if self.active_mode else "passive"
        logger.info(f"Starting LACP daemon in {mode_str} mode with configured rate: {self.rate_mode}")

        # Create sockets for each interface
        for port in self.ports:
            try:
                # Compatible with macOS which doesn't have AF_PACKET
                if hasattr(socket, "AF_PACKET"):
                    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x8809))
                    sock.bind((port.iface, 0))
                    self.sockets[port.iface] = sock
                else:
                    logger.error("socket.AF_PACKET is not available on this platform.")
                    self.stop()
                    return
            except Exception as e:
                logger.error(f"Could not bind to interface {port.iface}. Error: {e}")
                self.stop()
                return

        # Create threads for each port
        for port in self.ports:
            self.threads.append(threading.Thread(target=self._send_lacpdu, args=(port,)))
            self.threads.append(threading.Thread(target=self._listen_lacpdu, args=(port,)))

        # Create state machine updater and IPC server threads
        self.threads.append(threading.Thread(target=self._state_machine_updater))
        self.threads.append(threading.Thread(target=self._run_ipc_server))

        # Start all threads
        for thread in self.threads:
            thread.start()

        if self.active_mode:
            logger.info(
                "LACP daemon running in active mode. Transmission rate will adapt to partner's timeout setting."
            )
        else:
            logger.info("LACP daemon running in passive mode. Will only send LACPDUs when partner is active.")

    def stop(self) -> None:
        """Stop the LACP actor and clean up resources."""
        self.running = False
        logger.info("Stopping threads...")

        # Give threads a moment to exit their loops
        time.sleep(1.1)

        # Wait for threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=0.5)

        # Close all sockets
        for sock in self.sockets.values():
            sock.close()

        logger.info("LACP actor stopped.")
