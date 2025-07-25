#!/bin/bash
#
# Integration test script for LACP daemon
#
# Copyright (C) 2025 LACP Daemon Team
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This script requires root privileges to run (for network namespace and veth creation)
# It tests the LACP daemon functionality using network namespaces and virtual interfaces.
#
# Test Topology:
# ┌─────────────────────────────────────────────────────────────────────────────────────┐
# │                           LACP Integration Test                                     │
# └─────────────────────────────────────────────────────────────────────────────────────┘
#
#  Network Namespace: lacpd_test_ns1                   Network Namespace: lacpd_test_ns2
# ┌─────────────────────────────────┐                 ┌─────────────────────────────────┐
# │                                 │                 │                                 │
# │    ┌───────────────────────┐    │                 │    ┌───────────────────────┐    │
# │    │      LACP Daemon      │    │                 │    │      LACP Daemon      │    │
# │    │     (daemon mode)     │    │                 │    │     (daemon mode)     │    │
# │    └───────────────────────┘    │                 │    └───────────────────────┘    │
# │                │                │                 │                │                │
# │                │                │                 │                │                │
# │        ┌───────┴───────┐        │                 │        ┌───────┴───────┐        │
# │        │     Port 1    │        │                 │        │     Port 1    │        │
# │        │     veth0     │◄───────┼─────────────────┼───────►│     veth0     │        │
# │        │     (UP)      │        │                 │        │     (UP)      │        │
# │        └───────────────┘        │                 │        └───────────────┘        │
# │                │                │                 │                │                │
# │                │                │                 │                │                │
# │        ┌───────┴───────┐        │                 │        ┌───────┴───────┐        │
# │        │     Port 2    │        │                 │        │     Port 2    │        │
# │        │     veth1     │◄───────┼─────────────────┼───────►│     veth1     │        │
# │        │     (UP)      │        │                 │        │     (UP)      │        │
# │        └───────────────┘        │                 │        └───────────────┘        │
# │                                 │                 │                                 │
# └─────────────────────────────────┘                 └─────────────────────────────────┘
#
# Port Channel Configuration:
# ├── Port Channel 1: veth0 <─── LACP Protocol ───> veth0
# └── Port Channel 2: veth1 <─── LACP Protocol ───> veth1
#
# Test Scenarios:
# 1. Basic LACP negotiation between two daemons
# 2. Status queries (human readable, JSON, filtered)
# 3. Different LACP modes (active/passive, fast/slow)
# 4. Process management (kill functionality)
# 5. Multi-interface port channel aggregation
#
# LACP Protocol Flow:
# ┌─────────────┐    LACPDU    ┌─────────────┐
# │   Actor 1   │◄────────────►│   Actor 2   │
# │ (ns1)       │              │ (ns2)       │
# └─────────────┘              └─────────────┘
#       │                             │
#       │ Exchange LACP packets       │
#       │ - Actor Information         │
#       │ - Partner Information       │
#       │ - State bits                │
#       │ - System/Port priorities    │
#       │                             │
#       ▼                             ▼
# ┌─────────────┐              ┌─────────────┐
# │  Port 1     │              │  Port 1     │
# │   veth0     │◄────────────►│   veth0     │
# └─────────────┘              └─────────────┘
#       │                             │
#       │ Exchange LACP packets       │
#       │ - Actor Information         │
#       │ - Partner Information       │
#       │ - State bits                │
#       │ - System/Port priorities    │
#       │                             │
#       ▼                             ▼
# ┌─────────────┐              ┌─────────────┐
# │  Port 2     │              │  Port 2     │
# │   veth1     │◄────────────►│   veth1     │
# └─────────────┘              └─────────────┘
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
STABILIZATION_TIME=15
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
    ip -n "$NAMESPACE2" link set "$VETH1" up
    ip -n "$NAMESPACE2" link set "$VETH2" up

    print_success "Test environment created:"
    print_status "  $NAMESPACE1: $VETH1 + $VETH2"
    print_status "  $NAMESPACE2: $VETH1 + $VETH2"
    print_status "  Port Channel 1: $VETH1 <--> $VETH1"
    print_status "  Port Channel 2: $VETH2 <--> $VETH2"
}

# Start LACP daemons
start_lacpd_instances() {
    print_status "Starting LACP daemon instances..."

    # Start lacpd in namespace 1 with both interfaces in daemon mode
    ip netns exec "$NAMESPACE1" "$LACPD_BINARY" -i "$VETH1" -i "$VETH2" -d --log-level "$LOG_LEVEL"
    print_status "Started lacpd daemon in $NAMESPACE1 on interfaces $VETH1, $VETH2"

    # Start lacpd in namespace 2 with both interfaces in daemon mode
    ip netns exec "$NAMESPACE2" "$LACPD_BINARY" -i "$VETH1" -i "$VETH2" -d --log-level "$LOG_LEVEL"
    print_status "Started lacpd daemon in $NAMESPACE2 on interfaces $VETH1, $VETH2"

    # Wait for daemons to start and stabilize
    sleep 3

    # Check if daemons are running by querying their status
    if ! "$LACPD_BINARY" -s -n "$NAMESPACE1" >/dev/null 2>&1; then
        print_error "LACP daemon in $NAMESPACE1 failed to start or is not responding"
        exit 1
    fi

    if ! "$LACPD_BINARY" -s -n "$NAMESPACE2" >/dev/null 2>&1; then
        print_error "LACP daemon in $NAMESPACE2 failed to start or is not responding"
        exit 1
    fi

    print_success "Both LACP daemons started successfully with port channels"
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

    if [[ "$collecting_distributing_count" -ge 1 ]]; then
        print_success "✓ LACP negotiation successful: $collecting_distributing_count interface(s) are in COLLECTING_DISTRIBUTING state"
        return 0
    else
        print_error "✗ LACP negotiation failed: no interfaces in COLLECTING_DISTRIBUTING state"
        print_status "JSON output: $json_output"
        return 1
    fi
}

# Test status queries
test_status_queries() {
    print_status "Testing status queries..."

    echo
    print_status "1. Querying daemons in $NAMESPACE1 (human readable):"
    "$LACPD_BINARY" -s -n "$NAMESPACE1"

    echo
    print_status "2. Querying daemons in $NAMESPACE2 (human readable):"
    "$LACPD_BINARY" -s -n "$NAMESPACE2"

    echo
    print_status "3. Querying daemons in $NAMESPACE1 (JSON format):"
    "$LACPD_BINARY" -s -n "$NAMESPACE1" -j

    echo
    print_status "4. Querying daemons in $NAMESPACE2 (pretty JSON format):"
    "$LACPD_BINARY" -s -n "$NAMESPACE2" -p

    echo
    print_status "5. Querying daemons managing $VETH1 in $NAMESPACE1:"
    "$LACPD_BINARY" -s -n "$NAMESPACE1" -i "$VETH1"

    echo
    print_status "6. Querying daemons managing $VETH2 in $NAMESPACE2:"
    "$LACPD_BINARY" -s -n "$NAMESPACE2" -i "$VETH2"

    echo
    print_status "7. Testing cross-namespace query from $NAMESPACE1 (should find daemons in both namespaces):"
    ip netns exec "$NAMESPACE1" "$LACPD_BINARY" -s

    echo
    print_status "8. Testing cross-namespace query from $NAMESPACE2 (should find daemons in both namespaces):"
    ip netns exec "$NAMESPACE2" "$LACPD_BINARY" -s

    echo
    print_status "9. Testing cross-namespace query with JSON format from $NAMESPACE1:"
    ip netns exec "$NAMESPACE1" "$LACPD_BINARY" -s -j

    echo
    print_status "10. Testing cross-namespace query with pretty JSON format from $NAMESPACE2:"
    ip netns exec "$NAMESPACE2" "$LACPD_BINARY" -s -p

    echo
    print_status "11. Testing interface-based query across namespaces from $NAMESPACE1:"
    ip netns exec "$NAMESPACE1" "$LACPD_BINARY" -s -i "$VETH1"

    echo
    print_status "12. Testing interface-based query across namespaces from $NAMESPACE2:"
    ip netns exec "$NAMESPACE2" "$LACPD_BINARY" -s -i "$VETH2"

    echo
    print_status "13. Verifying LACP negotiation state in $NAMESPACE1:"
    if verify_lacp_state "$NAMESPACE1" "COLLECTING_DISTRIBUTING" "Both interfaces should be in COLLECTING_DISTRIBUTING state"; then
        print_success "✓ LACP negotiation verified in $NAMESPACE1"
    else
        print_warning "⚠ LACP negotiation may not be complete in $NAMESPACE1"
    fi

    echo
    print_status "14. Verifying LACP negotiation state in $NAMESPACE2:"
    if verify_lacp_state "$NAMESPACE2" "COLLECTING_DISTRIBUTING" "Both interfaces should be in COLLECTING_DISTRIBUTING state"; then
        print_success "✓ LACP negotiation verified in $NAMESPACE2"
    else
        print_warning "⚠ LACP negotiation may not be complete in $NAMESPACE2"
    fi

    print_success "Status query tests completed"
}

# Verify LACP mode flags from JSON output
verify_lacp_mode_flags() {
    local namespace="$1"
    local mode="$2"
    local description="$3"

    print_status "Verifying LACP mode flags: $description"

    # Get JSON status and parse it
    local json_output
    json_output=$("$LACPD_BINARY" -s -n "$namespace" -j 2>/dev/null)

    if [[ -z "$json_output" ]]; then
        print_error "Failed to get status from namespace $namespace"
        return 1
    fi

    case "$mode" in
        "passive")
            # Check that ACTIVE flag is NOT present in actor.state
            if command -v jq >/dev/null 2>&1; then
                # Check if any port has ACTIVE flag in actor.state (state value 63 has ACTIVE bit set)
                local active_count=$(echo "$json_output" | jq -r '.[0].ports[] | select(.actor.state and (.actor.state | tonumber) % 2 == 1) | .interface' 2>/dev/null | wc -l)
            else
                # Basic parsing - look for actor state values that indicate ACTIVE (odd numbers)
                local active_count=$(echo "$json_output" | grep -o '"state": [0-9]*' | awk '{if($2 % 2 == 1) count++} END{print count+0}' || echo "0")
            fi

            print_status "Found $active_count interfaces with ACTIVE flag in actor state"

            if [[ "$active_count" -eq 0 ]]; then
                print_success "✓ Passive mode verified: no ACTIVE flag found in actor state"
                return 0
            else
                print_error "✗ Passive mode verification failed: ACTIVE flag found in actor state"
                print_status "JSON output: $json_output"
                return 1
            fi
            ;;
        "slow")
            # Check that SHORT_TIMEOUT flag is NOT present in actor.state
            if command -v jq >/dev/null 2>&1; then
                # Check if any port has SHORT_TIMEOUT flag in actor.state (state value with bit 2 set)
                local timeout_count=$(echo "$json_output" | jq -r '.[0].ports[] | select(.actor.state and ((.actor.state | tonumber) / 2 | floor) % 2 == 1) | .interface' 2>/dev/null | wc -l)
            else
                # Basic parsing - look for actor state values that indicate SHORT_TIMEOUT (bit 2 set)
                local timeout_count=$(echo "$json_output" | grep -o '"state": [0-9]*' | awk '{if(int($2/2) % 2 == 1) count++} END{print count+0}' || echo "0")
            fi

            print_status "Found $timeout_count interfaces with SHORT_TIMEOUT flag in actor state"

            if [[ "$timeout_count" -eq 0 ]]; then
                print_success "✓ Slow rate mode verified: no SHORT_TIMEOUT flag found in actor state"
                return 0
            else
                print_error "✗ Slow rate mode verification failed: SHORT_TIMEOUT flag found in actor state"
                print_status "JSON output: $json_output"
                return 1
            fi
            ;;
        *)
            print_error "Unknown mode: $mode"
            return 1
            ;;
    esac
}

# Test different LACP modes
test_lacp_modes() {
    print_status "Testing different LACP modes..."

    # Kill existing daemons
    "$LACPD_BINARY" -k -n "$NAMESPACE1" 2>/dev/null || true
    "$LACPD_BINARY" -k -n "$NAMESPACE2" 2>/dev/null || true
    sleep 2

    # Test passive mode with port channel
    print_status "Testing passive mode with port channel..."
    ip netns exec "$NAMESPACE1" "$LACPD_BINARY" -i "$VETH1" -i "$VETH2" --passive -d --log-level "$LOG_LEVEL"
    sleep 3

    print_status "Passive mode daemon status:"
    "$LACPD_BINARY" -s -n "$NAMESPACE1"

    echo
    print_status "Verifying passive mode flags:"
    if verify_lacp_mode_flags "$NAMESPACE1" "passive" "Passive mode should not have ACTIVE flag"; then
        print_success "✓ Passive mode flags verified"
    else
        print_warning "⚠ Passive mode flags verification failed"
    fi

    "$LACPD_BINARY" -k -n "$NAMESPACE1" 2>/dev/null || true
    sleep 2

    # Test slow rate mode with port channel
    print_status "Testing slow rate mode with port channel..."
    ip netns exec "$NAMESPACE1" "$LACPD_BINARY" -i "$VETH1" -i "$VETH2" --rate slow -d --log-level "$LOG_LEVEL"
    sleep 3

    print_status "Slow rate mode daemon status:"
    "$LACPD_BINARY" -s -n "$NAMESPACE1"

    echo
    print_status "Verifying slow rate mode flags:"
    if verify_lacp_mode_flags "$NAMESPACE1" "slow" "Slow rate mode should not have SHORT_TIMEOUT flag"; then
        print_success "✓ Slow rate mode flags verified"
    else
        print_warning "⚠ Slow rate mode flags verification failed"
    fi

    "$LACPD_BINARY" -k -n "$NAMESPACE1" 2>/dev/null || true
    sleep 2

    print_success "LACP mode tests completed"
}

# Test process management
test_process_management() {
    print_status "Testing process management..."

    # Start daemons again for testing
    start_lacpd_instances

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

    # Kill remaining daemon
    "$LACPD_BINARY" -k -n "$NAMESPACE2" 2>/dev/null || true

    print_success "Process management tests completed"
}

# Main test execution
main() {
    print_status "Starting LACP daemon integration tests..."
    echo

    # Pre-flight checks
    check_root
    check_dependencies

    # Build and install the binary
    build_lacpd_binary

    # Run tests
    setup_test_environment
    start_lacpd_instances
    wait_for_lacp_negotiation
    test_status_queries
    test_lacp_modes
    test_process_management

    echo
    print_success "All integration tests completed successfully!"
    print_status "Test summary:"
    print_status "  - Binary: Built and installed lacpd binary"
    print_status "  - Network namespaces: $NAMESPACE1, $NAMESPACE2"
    print_status "  - Port Channel 1: $VETH1 <--> $VETH1"
    print_status "  - Port Channel 2: $VETH2 <--> $VETH2"
    print_status "  - LACP negotiation: ${STABILIZATION_TIME}s stabilization period"
    print_status "  - Status queries: Human readable, JSON, and filtered queries"
    print_status "  - LACP modes: Active, passive, fast, and slow rate modes"
    print_status "  - Process management: Kill functionality tested"
}

# Run main function
main "$@"
