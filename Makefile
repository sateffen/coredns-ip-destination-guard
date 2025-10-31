.PHONY: help init test test-coverage fmt vet clean genericbuild archlinux

# Default target
help:
	@echo "CoreDNS IP Destination Guard - Makefile targets:"
	@echo ""
	@echo "Development:"
	@echo "  make init          - Initialize development environment (install dependencies)"
	@echo "  make test          - Run all tests"
	@echo "  make test-coverage - Run tests with coverage report"
	@echo "  make fmt           - Format code with gofmt"
	@echo "  make vet           - Run go vet"
	@echo "  make clean         - Clean build artifacts and test cache"
	@echo ""
	@echo "Building:"
	@echo "  make genericbuild  - Build CoreDNS with this plugin (generic)"
	@echo "  make archlinux     - Build Arch Linux package"
	@echo ""

# Initialize development environment
init:
	@echo "Initializing development environment..."
	@if [ ! -f go.mod ]; then \
		echo "Creating go.mod..."; \
		go mod init github.com/steffenfritz/coredns-ip-destination-guard; \
	fi
	@echo "Downloading dependencies..."
	@go mod tidy
	@echo "Done! Run 'make test' to verify everything works."

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Format code
fmt:
	@echo "Formatting code..."
	@gofmt -w -s .
	@echo "Done!"

# Run go vet
vet:
	@echo "Running go vet..."
	@go vet ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@go clean -testcache
	@rm -f coverage.out coverage.html
	@rm -f go.mod go.sum
	@echo "Done!"

# Build CoreDNS with this plugin (generic build)
genericbuild:
	@echo "Building CoreDNS with ipdestinationguard plugin (generic)..."
	@cd genericbuild && bash build.sh
	@echo "Build complete! Binary should be in genericbuild/coredns/"

# Build Arch Linux package
archlinux:
	@echo "Building Arch Linux package..."
	@if [ ! -d archlinux ]; then \
		echo "Error: archlinux directory not found"; \
		exit 1; \
	fi
	@cd archlinux && makepkg -cC
	@echo "Package built! Check archlinux/ directory for .pkg.tar.zst file"

# Quick check before commit
check: fmt vet test
	@echo "All checks passed!"
