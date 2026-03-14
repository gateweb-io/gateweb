# Simple Makefile for Flow project
# Just the essentials - no complexity

.PHONY: help test clean

# Default target
help:
	@echo "Available commands:"
	@echo "  test    - Run all tests with race detection and coverage"
	@echo "  clean   - Clean up generated files"
	@echo "  help    - Show this help message"

# Run all tests
test:
	@echo "Running CI tests..."
	chmod +x scripts/ci.sh
	./scripts/ci.sh

# Clean up generated files
clean:
	@echo "Cleaning up..."
	rm -rf coverage/
	rm -rf *.out
	go clean -testcache
	go clean -cache 