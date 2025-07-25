"""
Unit tests for the packet module.

Tests LACP packet construction and parsing functionality.

Copyright (C) 2025 LACP Daemon Team
SPDX-License-Identifier: GPL-3.0-or-later
"""

import pytest

from lacpd.packet import build_ethernet_frame, build_lacpdu, parse_lacpdu


class TestLacpduConstruction:
    """Test LACPDU packet construction."""

    def test_build_lacpdu_valid_input(self):
        """Test building LACPDU with valid input."""
        actor_info = {
            "system_priority": 32768,
            "system": "00:11:22:33:44:55",
            "key": 1,
            "port_priority": 32768,
            "port": 1,
            "state": 0x3E,  # ACTIVE | SHORT_TIMEOUT | AGGREGATION | SYNC | COLLECTING | DISTRIBUTING
        }

        partner_info = {
            "system_priority": 32768,
            "system": "AA:BB:CC:DD:EE:FF",
            "key": 1,
            "port_priority": 32768,
            "port": 2,
            "state": 0x3E,
        }

        lacpdu = build_lacpdu(actor_info, partner_info)

        # Check that we get a bytes object
        assert isinstance(lacpdu, bytes)

        # Check minimum size (header + actor + partner + collector + terminator)
        assert len(lacpdu) >= 108

        # Check LACP header
        assert lacpdu[0] == 1  # subtype
        assert lacpdu[1] == 1  # version

        # Check Actor TLV
        assert lacpdu[2] == 1  # actor type
        assert lacpdu[3] == 20  # actor length

    def test_build_lacpdu_invalid_mac(self):
        """Test building LACPDU with invalid MAC address."""
        actor_info = {
            "system_priority": 32768,
            "system": "invalid_mac",
            "key": 1,
            "port_priority": 32768,
            "port": 1,
            "state": 0x3E,
        }

        partner_info = {
            "system_priority": 32768,
            "system": "AA:BB:CC:DD:EE:FF",
            "key": 1,
            "port_priority": 32768,
            "port": 2,
            "state": 0x3E,
        }

        with pytest.raises(ValueError, match="Invalid MAC address format"):
            build_lacpdu(actor_info, partner_info)


class TestLacpduParsing:
    """Test LACPDU packet parsing."""

    def test_parse_lacpdu_valid_packet(self):
        """Test parsing valid LACPDU packet."""
        # Create a minimal valid LACPDU
        lacpdu = bytes(
            [
                1,
                1,  # subtype, version
                1,
                20,  # Actor TLV type, length
                0x80,
                0x00,  # system_priority (32768)
                0x00,
                0x11,
                0x22,
                0x33,
                0x44,
                0x55,  # system MAC
                0x00,
                0x01,  # key
                0x80,
                0x00,  # port_priority (32768)
                0x00,
                0x01,  # port
                0x3E,  # state
                0x00,
                0x00,
                0x00,  # reserved
                # ... rest of packet would be filled with zeros
            ]
            + [0] * 100
        )  # Pad to minimum size

        result = parse_lacpdu(lacpdu)

        assert result is not None
        assert result["system_priority"] == 32768
        assert result["system"] == "00:11:22:33:44:55"
        assert result["key"] == 1
        assert result["port_priority"] == 32768
        assert result["port"] == 1
        assert result["state"] == 0x3E

    def test_parse_lacpdu_too_short(self):
        """Test parsing LACPDU that's too short."""
        short_packet = bytes([1, 1, 1, 20])  # Too short

        result = parse_lacpdu(short_packet)
        assert result is None

    def test_parse_lacpdu_invalid_format(self):
        """Test parsing LACPDU with invalid format."""
        invalid_packet = bytes([1, 1] + [0] * 50)  # Invalid structure

        result = parse_lacpdu(invalid_packet)
        # Should handle gracefully and return None
        assert result is None


class TestEthernetFrame:
    """Test Ethernet frame construction."""

    def test_build_ethernet_frame_valid(self):
        """Test building Ethernet frame with valid MAC addresses."""
        dest_mac = "01:80:c2:00:00:02"
        src_mac = "00:11:22:33:44:55"
        payload = b"test_payload"

        frame = build_ethernet_frame(dest_mac, src_mac, payload)

        assert isinstance(frame, bytes)
        assert len(frame) == 14 + len(payload)  # 14-byte header + payload

        # Check Ethernet header
        dest_bytes = frame[0:6]
        src_bytes = frame[6:12]
        protocol = frame[12:14]

        assert dest_bytes == bytes.fromhex(dest_mac.replace(":", ""))
        assert src_bytes == bytes.fromhex(src_mac.replace(":", ""))
        assert protocol == b"\x88\x09"  # Slow protocols

    def test_build_ethernet_frame_invalid_mac(self):
        """Test building Ethernet frame with invalid MAC address."""
        dest_mac = "invalid_mac"
        src_mac = "00:11:22:33:44:55"
        payload = b"test_payload"

        with pytest.raises(ValueError, match="Invalid MAC address format"):
            build_ethernet_frame(dest_mac, src_mac, payload)


class TestRoundTrip:
    """Test round-trip packet construction and parsing."""

    def test_lacpdu_round_trip(self):
        """Test that we can build and parse LACPDU correctly."""
        actor_info = {
            "system_priority": 32768,
            "system": "00:11:22:33:44:55",
            "key": 1,
            "port_priority": 32768,
            "port": 1,
            "state": 0x3E,
        }

        partner_info = {
            "system_priority": 32768,
            "system": "AA:BB:CC:DD:EE:FF",
            "key": 1,
            "port_priority": 32768,
            "port": 2,
            "state": 0x3E,
        }

        # Build LACPDU
        lacpdu = build_lacpdu(actor_info, partner_info)

        # Parse it back
        parsed = parse_lacpdu(lacpdu)

        # Should get the actor info (which represents our partner)
        assert parsed is not None
        assert parsed["system_priority"] == actor_info["system_priority"]
        assert parsed["system"] == actor_info["system"]
        assert parsed["key"] == actor_info["key"]
        assert parsed["port_priority"] == actor_info["port_priority"]
        assert parsed["port"] == actor_info["port"]
        assert parsed["state"] == actor_info["state"]