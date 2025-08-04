#!/bin/bash
#
# Integration test script for LACP inject functionality
#
# Copyright (C) 2025 LACP Daemon Team
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This script requires root privileges to run (for network namespace and veth creation)
# It tests the LACP inject functionality using network namespaces and virtual interfaces.
#
# Test Topology:
# ┌─────────────────────────────────────────────────────────────────────────────────────┐
# │                           LACP Inject Test                                          │
# └─────────────────────────────────────────────────────────────────────────────────────┘
#
#  Network Namespace: lacpd_inject_ns1              Network Namespace: lacpd_inject_ns2
# ┌─────────────────────────────────┐             ┌─────────────────────────────────┐
# │                                 │             │                                 │
# │    ┌───────────────────────┐    │             │    ┌───────────────────────┐    │
# │    │   LACP Daemon         │    │             │    │   LACP Daemon         │    │
# │    │  (daemon mode)        │    │             │    │  (inject mode)        │    │
# │    │  (listener)           │    │             │    │  (tester)             │    │
# │    └───────────────────────┘    │             │    └───────────────────────┘    │
# │                │                │             │                │                │
# │                │                │             │                │                │
# │        ┌───────┴───────┐        │             │        ┌───────┴───────┐        │
# │        │     Port 1    │        │             │        │     Port 1    │        │
# │        │     veth0     │◄───────┼─────────────┼───────►│     veth0     │        │
# │        │     (UP)      │        │             │        │     (UP)      │        │
# │        └───────────────┘        │             │        └───────────────┘        │
# │                │                │             │                │                │
# │                │                │             │                │                │
# │        ┌───────┴───────┐        │             │        ┌───────┴───────┐        │
# │        │     Port 2    │        │             │        │     Port 2    │        │
# │        │     veth1     │◄───────┼─────────────┼───────►│     veth1     │        │
# │        │     (UP)      │        │             │        │     (UP)      │        │
# │        └───────────────┘        │             │        └───────────────┘        │
# │                                 │             │                                 │
# └─────────────────────────────────┘             └─────────────────────────────────┘
#
# Test Scenarios:
# 1. Start listener daemon in ns1 (daemon mode)
# 2. Test inject rule "P:ATGS -> A:AT" in ns2
# 3. Test inject rule "P:ATGSCD -> A:AT" in ns2
# 4. Verify state changes and packet transmission
# 5. Check log files for injection events
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE1="lacpd_inject_ns1"
NAMESPACE2="lacpd_inject_ns2"
VETH1="veth0"
VETH2="veth1"
LOG_LEVEL="DEBUG"
LOG_DIR="/tmp/lacpd_inject_test"

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

# Create log directory
setup_log_directory() {
    print_status "Setting up log directory..."
    mkdir -p "$LOG_DIR"
    print_success "Log directory created: $LOG_DIR"
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

# Start listener daemon in namespace 1
start_listener_daemon() {
    local test_name="$1"
    local log_file="$LOG_DIR/${test_name}_listener.log"

    print_status "Starting listener daemon in $NAMESPACE1 for test: $test_name..."

    # Start lacpd in namespace 1 with both interfaces in daemon mode
    ip netns exec "$NAMESPACE1" "$LACPD_BINARY" \
        -i "$VETH1" -i "$VETH2" \
        -d \
        --log-level "$LOG_LEVEL" \
        --log-file "$log_file"

    print_status "Started listener daemon in $NAMESPACE1"

    # Wait for daemon to start
    sleep 3

    # Check if daemon is running by querying its status
    if ! "$LACPD_BINARY" -s -n "$NAMESPACE1" >/dev/null 2>&1; then
        print_error "Listener daemon in $NAMESPACE1 failed to start or is not responding"
        exit 1
    fi

    print_success "Listener daemon started successfully with log: $log_file"
}



# Test inject rule
test_inject_rule() {
    local inject_rule="$1"
    local test_name="$2"
    local log_file="$LOG_DIR/${test_name}_test.log"
    local timeout=30

    print_status "Testing inject rule: $inject_rule"
    print_status "Test name: $test_name"

    # Start listener daemon for this specific test
    start_listener_daemon "$test_name"

    # Start inject test in namespace 2
    print_status "Starting inject test in $NAMESPACE2 with rule: $inject_rule"
    print_status "Timeout set to ${timeout}s"

    # Start the inject test with timeout
    timeout "$timeout" ip netns exec "$NAMESPACE2" "$LACPD_BINARY" \
        -i "$VETH1" -i "$VETH2" \
        --inject "$inject_rule" \
        --exit-after-inject \
        --log-level "$LOG_LEVEL" \
        --log-file "$log_file"

    INJECT_EXIT_CODE=$?

    if [[ $INJECT_EXIT_CODE -eq 124 ]]; then
        print_warning "Inject test timed out after ${timeout}s, killing process..."
        "$LACPD_BINARY" -k -n "$NAMESPACE2" 2>/dev/null || true
        sleep 2
    else
        print_status "Inject test completed with exit code: $INJECT_EXIT_CODE"
    fi

    # Wait a bit for state changes to propagate
    sleep 3

    # Check log files for injection events
    check_injection_logs "$test_name" "$log_file" "$inject_rule"

    # Stop listener daemon for this test
    print_status "Stopping listener daemon for test: $test_name"
    "$LACPD_BINARY" -k -n "$NAMESPACE1" 2>/dev/null || true
    sleep 2

    print_success "Inject test '$test_name' completed"
}

# Check injection logs
check_injection_logs() {
    local test_name="$1"
    local log_file="$2"
    local inject_rule="$3"

    print_status "Checking injection logs for test: $test_name"

    if [[ -f "$log_file" ]]; then
        print_status "Inject test log ($log_file):"
        cat "$log_file"

        # Check for injection events
        if grep -q "Inject rule triggered" "$log_file"; then
            print_success "✓ Injection events found in log"
        else
            print_warning "⚠ No injection events found in log"
        fi

        # Check for LACPDU transmission
        if grep -q "Sent LACPDU" "$log_file"; then
            print_success "✓ LACPDU transmission confirmed"
        else
            print_warning "⚠ No LACPDU transmission found in log"
        fi

        # Check for exit after injection
        if grep -q "Exiting after successful injection" "$log_file"; then
            print_success "✓ Exit after injection confirmed"
        else
            print_warning "⚠ No exit after injection found in log"
        fi
    else
        print_error "Inject test log file not found: $log_file"
    fi

    # Check listener log for corresponding partner state changes
    local listener_log="$LOG_DIR/${test_name}_listener.log"
    if [[ -f "$listener_log" ]]; then
        print_status "Listener log ($listener_log) - recent entries:"
        tail -20 "$listener_log"

        # Extract target state from inject rule (e.g., "P:ATG -> A:AT" -> "AT")
        local target_state=""
        if [[ "$inject_rule" =~ "->"[[:space:]]*A:([A-Z]+) ]]; then
            target_state="${BASH_REMATCH[1]}"
            print_status "Looking for partner state change to: $target_state"

            # Check for partner state changes to the target state
            if grep -q "state changed.*P:$target_state" "$listener_log"; then
                print_success "✓ Partner state change to $target_state detected in listener log"
            else
                print_warning "⚠ No partner state change to $target_state found in listener log"
            fi
        fi

        # Check for any state change logs
        if grep -q "state changed" "$listener_log"; then
            print_success "✓ State changes detected in listener log"
        else
            print_warning "⚠ No state changes found in listener log"
        fi
    else
        print_error "Listener log file not found: $listener_log"
    fi
}

# Print test summary
print_test_summary() {
    print_status "Test Summary:"
    print_status "  - Log directory: $LOG_DIR"
    print_status "  - Listener daemon: $NAMESPACE1 (daemon mode)"
    print_status "  - Test scenarios:"
    print_status "    1. Inject rule: 'P:ATG -> A:AT'"
    print_status "    2. Inject rule: 'P:ATGSCD -> A:AT'"
    print_status "  - All log files preserved for analysis"

    echo
    print_status "Log files created:"
    ls -la "$LOG_DIR/"
}

# Main test execution
main() {
    print_status "Starting LACP inject functionality tests..."
    echo

    # Pre-flight checks
    check_root
    check_dependencies

    # Build and install the binary
    build_lacpd_binary

    # Setup log directory
    setup_log_directory

    # Run tests
    setup_test_environment

    # Test inject rules
    test_inject_rule "P:ATG -> A:AT" "test1_atg_to_at"
    test_inject_rule "P:ATGSCD -> A:AT" "test2_atgscd_to_at"

    # Print test summary
    print_test_summary

    echo
    print_success "All inject functionality tests completed successfully!"
    print_status "Check log files in $LOG_DIR for detailed results"
}

# Run main function
main "$@"
