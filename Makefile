# Makefile for LACP Daemon
#
# Copyright (C) 2025 LACP Daemon Team
# SPDX-License-Identifier: GPL-3.0-or-later

.PHONY: help install install-dev test test-unit test-integration lint format type-check clean build dist binary

# Default target
help:
	@echo "Available targets:"
	@echo "  install        - Install the package"
	@echo "  install-dev    - Install the package with development dependencies"
	@echo "  test           - Run all tests"
	@echo "  test-unit      - Run unit tests only"
	@echo "  test-integration - Run integration tests (requires root)"
	@echo "  lint           - Run linting checks"
	@echo "  format         - Format code with black and ruff"
	@echo "  type-check     - Run type checking with mypy"
	@echo "  clean          - Clean build artifacts"
	@echo "  build          - Build the package"
	@echo "  dist           - Create distribution packages"
	@echo "  binary         - Build standalone executable binary"

# Installation
install:
	uv sync

install-dev:
	uv sync --dev

# Testing
test: test-unit

test-unit:
	uv run pytest tests/ -v --tb=short

test-integration:
	@echo "Running integration tests (requires root privileges)..."
	sudo uv run bash tests/run_test.sh

# Code quality
lint:
	uv run ruff check src/ tests/
	uv run black --check src/ tests/
	uv run mypy src/

format:
	uv run black src/ tests/
	uv run ruff format src/ tests/

type-check:
	uv run mypy src/

# Cleanup
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf __pycache__/
	rm -rf .pyinstaller/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Build
build: clean
	uv build

dist: build
	@echo "Distribution packages created in dist/ directory"

# Binary compilation
binary: clean
	@echo "Building standalone executable binary..."
	uv sync --group build
	uv run pyinstaller lacpd.spec --clean
	@echo "Binary created: dist/lacpd"
	@echo "You can run it directly: ./dist/lacpd --help"

binary-debug: clean
	@echo "Building standalone executable binary (debug mode)..."
	uv sync --group build
	uv run pyinstaller lacpd.spec --clean --debug
	@echo "Debug binary created: dist/lacpd"

# Development helpers
dev-install:
	uv sync --dev
	uv run pre-commit install

dev-check:
	uv run ruff check src/ tests/
	uv run black --check src/ tests/
	uv run mypy src/
	uv run pytest tests/ --cov=lacpd --cov-report=term-missing
