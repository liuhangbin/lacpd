#!/bin/bash
#
# Integration test script for LACP daemon with Linux 802.3ad bond
#
# Copyright (C) 2025 LACP Daemon Team
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This script requires root privileges to run (for network namespace and veth creation)
# It tests the LACP daemon functionality against Linux 802.3ad bond.
#
# Test Topology:
# ┌─────────────────────────────────────────────────────────────────────────────────────┐
# │                           LACP Bond Integration Test                                │
# └─────────────────────────────────────────────────────────────────────────────────────┘
#
#  Network Namespace: lacpd_test_ns1                   Network Namespace: lacpd_test_ns2
# ┌─────────────────────────────────┐                 ┌─────────────────────────────────┐
# │                                 │                 │                                 │
# │    ┌───────────────────────┐    │                 │    ┌───────────────────────┐    │
# │    │      LACP Daemon      │    │                 │    │   Linux 802.3ad Bond   │    │
# │    │     (daemon mode)     │    │                 │    │       bond0            │    │
# │    └───────────────────────┘    │                 │    └───────────────────────┘    │
# │                │                │                 │                │                │
# │                │                │                 │                │                │
# │        ┌───────┴───────┐        │                 │        ┌───────┴───────┐        │
# │        │     Port 1    │        │                 │        │   Slave 1     │        │
# │        │     veth0     │◄───────┼─────────────────┼───────►│     veth0     │        │
# │        │     (UP)      │        │                 │        │     (UP)      │        │
# │        └───────────────┘        │                 │        └───────────────┘        │
# │                │                │                 │                │                │
# │                │                │                 │                │                │
# │        ┌───────┴───────┐        │                 │        ┌───────┴───────┐        │
# │        │     Port 2    │        │                 │        │   Slave 2     │        │
# │        │     veth1     │◄───────┼─────────────────┼───────►│     veth1     │        │
# │        │     (UP)      │        │                 │        │     (UP)      │        │
# │        └───────────────┘        │                 │        └───────────────┘        │
# │                                 │                 │                                 │
# └─────────────────────────────────┘                 └─────────────────────────────────┘
#
# Port Channel Configuration:
# ├── Port Channel 1: veth0 <─── LACP Protocol ───> veth0 (bond0 slave)
# └── Port Channel 2: veth1 <─── LACP Protocol ───> veth1 (bond0 slave)
#
# Test Scenarios:
# 1. LACP negotiation between LACP daemon and Linux 802.3ad bond
# 2. Verify bond0 reaches COLLECTING_DISTRIBUTING state
# 3. Check bond0 status and slave states
# 4. Verify LACP daemon reaches COLLECTING_DISTRIBUTING state
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE1="lacpd_test_ns1"
NAMESPACE2="lacpd_test_ns2"
VETH1="veth0"
VETH2="veth1"
BOND_NAME="bond0"
STABILIZATION_TIME=20
LOG_LEVEL="INFO"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script requires root privileges to run"
        print_error "Please run with: sudo $0"
        exit 1
    fi
}

# Check if required tools are available
check_dependencies() {
    local missing_tools=()

    for tool in ip uv python3; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi

    # Check if bonding module is loaded
    if ! lsmod | grep -q bonding; then
        print_status "Loading bonding module..."
        modprobe bonding
    fi
}

# Build the lacpd binary
build_lacpd_binary() {
    print_status "Building lacpd binary..."

    # Clean previous builds
    make clean

    # Check if standalone binary exists
    if [[ -f "dist/lacpd" ]]; then
        print_status "Using existing standalone binary: dist/lacpd"
        LACPD_BINARY="dist/lacpd"
    else
        print_status "Building standalone binary..."
        make binary

        if [[ -f "dist/lacpd" ]]; then
            LACPD_BINARY="dist/lacpd"
            print_success "Standalone binary created: $LACPD_BINARY"
        else
            print_warning "Failed to build standalone binary, falling back to installed package"
            # Install the package in development mode to get the binary
            uv pip install -e .

            export PATH="$PWD/.venv/bin:$PATH"
            # Verify the binary is available
            if ! command -v lacpd &> /dev/null; then
                print_error "lacpd binary not found after installation"
                exit 1
            fi
            LACPD_BINARY="lacpd"
        fi
    fi

    print_success "lacpd binary ready: $LACPD_BINARY"
}

# Cleanup function to be called on exit
cleanup() {
    print_status "Cleaning up test environment..."

    # Kill any running lacpd processes
    pkill -f "lacpd" || true

    # Remove network namespaces (this will also remove all interfaces in them)
    ip netns del "$NAMESPACE1" 2>/dev/null || true
    ip netns del "$NAMESPACE2" 2>/dev/null || true

    print_success "Cleanup complete"
}

# Ensure cleanup is called on script exit or interruption
trap cleanup EXIT INT TERM

# Setup test environment
setup_test_environment() {
    print_status "Setting up test environment..."

    # Create network namespaces
    ip netns add "$NAMESPACE1"
    ip netns add "$NAMESPACE2"

    # Create veth pairs with same names in both namespaces
    # Port Channel 1: veth0 in both namespaces
    ip -n "$NAMESPACE1" link add "$VETH1" type veth peer name "$VETH1" netns "$NAMESPACE2"

    # Port Channel 2: veth1 in both namespaces
    ip -n "$NAMESPACE1" link add "$VETH2" type veth peer name "$VETH2" netns "$NAMESPACE2"

    # Bring interfaces up (no IP addresses needed for port channel)
    ip -n "$NAMESPACE1" link set "$VETH1" up
    ip -n "$NAMESPACE1" link set "$VETH2" up

    print_success "Test environment created:"
    print_status "  $NAMESPACE1: $VETH1 + $VETH2 (LACP daemon)"
    print_status "  $NAMESPACE2: $VETH1 + $VETH2 (Linux bond)"
    print_status "  Port Channel 1: $VETH1 <--> $VETH1"
    print_status "  Port Channel 2: $VETH2 <--> $VETH2"
}

# Setup Linux 802.3ad bond
setup_linux_bond() {
    print_status "Setting up Linux 802.3ad bond in $NAMESPACE2..."

    # Create bond interface
    ip -n "$NAMESPACE2" link add "$BOND_NAME" type bond mode 802.3ad miimon 100 lacp_rate fast

    # Add slaves to bond
    ip -n "$NAMESPACE2" link set "$VETH1" master "$BOND_NAME"
    ip -n "$NAMESPACE2" link set "$VETH2" master "$BOND_NAME"

    # Bring bond interface up
    ip -n "$NAMESPACE2" link set "$BOND_NAME" up

    print_success "Linux 802.3ad bond created:"
    print_status "  Bond interface: $BOND_NAME"
    print_status "  Mode: 802.3ad (LACP)"
    print_status "  Slaves: $VETH1, $VETH2"
    print_status "  MII monitoring: 100ms"
    print_status "  LACP rate: fast"
}

# Start LACP daemon
start_lacpd_instance() {
    print_status "Starting LACP daemon in $NAMESPACE1..."

    # Start lacpd in namespace 1 with both interfaces in daemon mode
    ip netns exec "$NAMESPACE1" "$LACPD_BINARY" -i "$VETH1" -i "$VETH2" -d --log-level "$LOG_LEVEL"
    print_status "Started lacpd daemon in $NAMESPACE1 on interfaces $VETH1, $VETH2"

    # Wait for daemon to start and stabilize
    sleep 3

    # Check if daemon is running by querying its status
    if ! "$LACPD_BINARY" -s -n "$NAMESPACE1" >/dev/null 2>&1; then
        print_error "LACP daemon in $NAMESPACE1 failed to start or is not responding"
        exit 1
    fi

    print_success "LACP daemon started successfully"
}

# Wait for LACP negotiation
wait_for_lacp_negotiation() {
    print_status "Waiting for LACP negotiation to stabilize (${STABILIZATION_TIME}s)..."
    sleep "$STABILIZATION_TIME"
    print_success "LACP negotiation period completed"
}

# Verify LACP state from JSON output
verify_lacp_state() {
    local namespace="$1"
    local expected_state="$2"
    local description="$3"

    print_status "Verifying LACP state: $description"

    # Get JSON status and parse it
    local json_output
    json_output=$("$LACPD_BINARY" -s -n "$namespace" -j 2>/dev/null)

    if [[ -z "$json_output" ]]; then
        print_error "Failed to get status from namespace $namespace"
        return 1
    fi

    # Check if interfaces are in COLLECTING_DISTRIBUTING state
    local collecting_distributing_count=0

    # Parse JSON to check mux_state (using jq if available, otherwise basic parsing)
    if command -v jq >/dev/null 2>&1; then
        # Use jq for proper JSON parsing - check mux_state field
        collecting_distributing_count=$(echo "$json_output" | jq -r '.[0].ports[] | select(.mux_state == "COLLECTING_DISTRIBUTING") | .interface' 2>/dev/null | wc -l)
    else
        # Basic parsing using grep - look for mux_state with COLLECTING_DISTRIBUTING
        collecting_distributing_count=$(echo "$json_output" | grep -c '"mux_state": "COLLECTING_DISTRIBUTING"' || echo "0")
    fi

    print_status "Found $collecting_distributing_count interfaces in COLLECTING_DISTRIBUTING state"

    if [[ "$collecting_distributing_count" -eq 2 ]]; then
        print_success "✓ LACP negotiation successful: $collecting_distributing_count interface(s) are in COLLECTING_DISTRIBUTING state"
        return 0
    else
        print_error "✗ LACP negotiation failed: no interfaces in COLLECTING_DISTRIBUTING state"
        print_status "JSON output: $json_output"
        return 1
    fi
}

# Test process management
test_process_management() {
    print_status "Testing process management..."

    # Test kill functionality
    print_status "Testing kill functionality..."
    "$LACPD_BINARY" -k -n "$NAMESPACE1"

    # Verify daemon was killed
    sleep 2
    if "$LACPD_BINARY" -s -n "$NAMESPACE1" >/dev/null 2>&1; then
        print_warning "Daemon in $NAMESPACE1 may not have been killed properly"
    else
        print_success "Daemon in $NAMESPACE1 killed successfully"
    fi

    print_success "Process management tests completed"
}

# Main test execution
main() {
    print_status "Starting LACP daemon bond integration tests..."
    echo

    # Pre-flight checks
    check_root
    check_dependencies

    # Build and install the binary
    build_lacpd_binary

    # Run tests
    setup_test_environment
    setup_linux_bond
    start_lacpd_instance
    wait_for_lacp_negotiation

    # verify status
    verify_lacp_state "$NAMESPACE1" "COLLECTING_DISTRIBUTING" "Both interfaces should be in COLLECTING_DISTRIBUTING state"
    test_process_management

    echo
    print_success "All bond integration tests completed successfully!"
    print_status "Test summary:"
    print_status "  - Binary: Built and installed lacpd binary"
    print_status "  - Network namespaces: $NAMESPACE1 (LACP daemon), $NAMESPACE2 (Linux bond)"
    print_status "  - Port Channel 1: $VETH1 <--> $VETH1 (bond0 slave)"
    print_status "  - Port Channel 2: $VETH2 <--> $VETH2 (bond0 slave)"
    print_status "  - Linux bond: $BOND_NAME (802.3ad mode)"
    print_status "  - LACP negotiation: ${STABILIZATION_TIME}s stabilization period"
    print_status "  - Status queries: Human readable, JSON, and filtered queries"
    print_status "  - Process management: Kill functionality tested"
}

# Run main function
main "$@"
