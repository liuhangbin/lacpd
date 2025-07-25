"""
LACP (Link Aggregation Control Protocol) Daemon

A Python implementation of the LACP daemon for simulating LACP negotiation process.
This package provides functionality to create, manage, and monitor LACP actors
for network interface aggregation testing.

Copyright (C) 2025 LACP Daemon Team
SPDX-License-Identifier: GPL-3.0-or-later

Example:
    >>> from lacpd import LacpActor
    >>> actor = LacpActor(['eth0', 'eth1'], rate_mode='fast', active_mode=True)
    >>> actor.start()
    >>> # ... use the actor
    >>> actor.stop()
"""

__version__ = "1.0.0"
__author__ = "LACP Daemon Team"
__email__ = "team@example.com"

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
    get_netns_id,
)

__all__ = [
    "LacpActor",
    "LACP_STATE_ACTIVE",
    "LACP_STATE_SHORT_TIMEOUT",
    "LACP_STATE_AGGREGATION",
    "LACP_STATE_SYNC",
    "LACP_STATE_COLLECTING",
    "LACP_STATE_DISTRIBUTING",
    "LACP_STATE_DEFAULTED",
    "LACP_STATE_EXPIRED",
    "LACP_RATE_FAST",
    "LACP_RATE_SLOW",
    "get_netns_id",
]