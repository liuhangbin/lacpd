"""
LACP Packet Processing

This module handles the construction and parsing of LACPDU
(Link Aggregation Control Protocol Data Unit) packets.

Copyright (C) 2025 LACP Daemon Team
SPDX-License-Identifier: GPL-3.0-or-later
"""

import struct


def build_lacpdu(actor_info: dict, partner_info: dict) -> bytes:
    """
    Build an LACPDU frame according to IEEE 802.3ad specification.

    Args:
        actor_info: Actor information dictionary containing:
            - system_priority: System priority (16-bit)
            - system: System MAC address (string)
            - key: Aggregation key (16-bit)
            - port_priority: Port priority (16-bit)
            - port: Port number (16-bit)
            - state: State bits (8-bit)
        partner_info: Partner information dictionary with same structure as actor_info

    Returns:
        LACPDU payload as bytes

    Raises:
        ValueError: If MAC address format is invalid
    """
    # LACP Header
    subtype = 1
    version = 1

    # Actor Information TLV
    actor_type = 1
    actor_info_len = 20

    # Partner Information TLV
    partner_type = 2
    partner_info_len = 20

    # Collector Information TLV
    collector_type = 3
    collector_info_len = 16
    collector_max_delay = 0

    # Terminator TLV
    terminator_type = 0
    terminator_len = 0
    terminator_reserved = b"\x00" * 50

    # Convert MAC strings to bytes
    try:
        actor_system_bytes = bytes.fromhex(actor_info["system"].replace(":", ""))
        partner_system_bytes = bytes.fromhex(partner_info["system"].replace(":", ""))
    except ValueError as e:
        raise ValueError(f"Invalid MAC address format: {e}") from e

    # Pack the LACPDU using separate struct.pack calls for clarity
    # LACP Header
    header = struct.pack("!BB", subtype, version)

    # Actor TLV
    actor_tlv = struct.pack(
        "!BBH6sHHHB3s",
        actor_type,
        actor_info_len,
        actor_info["system_priority"],
        actor_system_bytes,
        actor_info["key"],
        actor_info["port_priority"],
        actor_info["port"],
        actor_info["state"],
        b"\x00\x00\x00",  # Reserved
    )

    # Partner TLV
    partner_tlv = struct.pack(
        "!BBH6sHHHB3s",
        partner_type,
        partner_info_len,
        partner_info["system_priority"],
        partner_system_bytes,
        partner_info["key"],
        partner_info["port_priority"],
        partner_info["port"],
        partner_info["state"],
        b"\x00\x00\x00",  # Reserved
    )

    # Collector TLV
    collector_tlv = struct.pack("!BBH12s", collector_type, collector_info_len, collector_max_delay, b"\x00" * 12)

    # Terminator TLV
    terminator_tlv = struct.pack("!BB50s", terminator_type, terminator_len, terminator_reserved)

    return header + actor_tlv + partner_tlv + collector_tlv + terminator_tlv


def parse_lacpdu(payload: bytes) -> dict | None:
    """
    Parse a raw LACPDU payload and extract the Actor's information.

    Args:
        payload: Raw LACPDU payload bytes

    Returns:
        Dictionary containing actor information or None if parsing fails:
            - system_priority: System priority (16-bit)
            - system: System MAC address (string)
            - key: Aggregation key (16-bit)
            - port_priority: Port priority (16-bit)
            - port: Port number (16-bit)
            - state: State bits (8-bit)
    """
    try:
        # Unpack the Actor TLV, which is our partner's information
        # LACPDU starts with 2 bytes (subtype, version), then Actor TLV starts at offset 2
        # Actor TLV: type(1) + len(1) + system_priority(2) + system_mac(6) + key(2) +
        # port_priority(2) + port(2) + state(1) + reserved(3) = 20 bytes
        actor_info_start = 2  # Skip header, start at Actor TLV
        actor_info_end = actor_info_start + 20  # Actor TLV is 20 bytes

        if len(payload) < actor_info_end:
            return None

        # Basic validation: check LACP header and Actor TLV type
        if payload[0] != 1 or payload[1] != 1:  # Check subtype and version
            return None

        if payload[actor_info_start] != 1:  # Check Actor TLV type
            return None

        # Extract Actor TLV data (skip type and len, start with system_priority)
        actor_data = payload[actor_info_start + 2 : actor_info_end - 3]  # Skip type, len, and reserved

        # Unpack: system_priority(2) + system_mac(6) + key(2) + port_priority(2) + port(2) + state(1)
        (system_priority, system_bytes, key, port_priority, port, state) = struct.unpack("!H6sHHHB", actor_data)

        system_mac = ":".join(f"{b:02x}" for b in system_bytes)

        return {
            "system_priority": system_priority,
            "system": system_mac,
            "key": key,
            "port_priority": port_priority,
            "port": port,
            "state": state,
        }
    except (struct.error, IndexError):
        return None


def build_ethernet_frame(dest_mac: str, src_mac: str, payload: bytes) -> bytes:
    """
    Build a complete Ethernet frame with LACPDU payload.

    Args:
        dest_mac: Destination MAC address (colon-separated hex string)
        src_mac: Source MAC address (colon-separated hex string)
        payload: LACPDU payload bytes

    Returns:
        Complete Ethernet frame as bytes

    Raises:
        ValueError: If MAC address format is invalid
    """
    # Ethernet Header
    eth_protocol = 0x8809  # Slow protocols

    try:
        dest_mac_bytes = bytes.fromhex(dest_mac.replace(":", ""))
        src_mac_bytes = bytes.fromhex(src_mac.replace(":", ""))
    except ValueError as e:
        raise ValueError(f"Invalid MAC address format: {e}") from e

    eth_header = struct.pack("!6s6sH", dest_mac_bytes, src_mac_bytes, eth_protocol)

    return eth_header + payload