# Global variables
PROJECTNAME=coredns-ip-destination-guard
# Go related variables.
DISTPATH=dist
GOFILES=$(shell find . -type f -name '*.go' -not -path './vendor/*')

.DEFAULT_GOAL := help

## clean: Clean the projects dist folder
.PHONY: clean
clean:
	@echo " > Cleaning dist folder..."
	@rm -rf dist
	@[ -e archlinux/src ] && chmod -R +w archlinux/src || true
	@rm -rf archlinux/src
	@rm -rf archlinux/*.tar.gz
	@rm -rf archlinux/*.pkg.tar.zst
	@[ -e genericbuild/src ] && chmod -R +w genericbuild/src || true
	@rm -rf genericbuild/src
	@rm -rf genericbuild/*.tar.gz
	@[ -e testbuild/src ] && chmod -R +w testbuild/src || true
	@rm -rf testbuild/src
	@rm -rf testbuild/*.tar.gz
	@rm -rf testbuild/coredns
	@echo " > Done..."

.PHONY: clean-nft
clean-nft:
	@echo " > Cleaning nftables..."
	@sudo nft delete table inet coredns-ip-destination-guard
	@echo " > Done..."

# Initialize development environment
.PHONY: init
init:
	@echo "Initializing development environment..."
	@if [ ! -f go.mod ]; then \
		echo "Creating go.mod..."; \
		go mod init github.com/sateffen/coredns-ip-destination-guard; \
	fi
	@echo "Downloading dependencies..."
	@go mod tidy
	@go mod vendor
	@echo "Done! Run 'make test' to verify everything works."

## lint: Run the linter on the project
.PHONY: lint
lint:
	@echo " > Running linter..."
	@golangci-lint run

## test: Run all tests in the project
.PHONY: test
test:
	@echo " > Running tests..."
	@go test -mod=vendor ./...

## build: Build the project
.PHONY: build
build: $(DISTPATH)/$(PROJECTNAME)

## install-dependencies: Install all necessary dependencies for this project
.PHONY: install-dependencies
install-dependencies:
	@echo " > Installing missing dependencies to cache..."
	@go mod tidy
	@echo " > Creating vendor cache..."
	@go mod vendor
	@echo " > Done..."

testbuild/src:
	@echo " > Preparing testbuild..."
	@cd testbuild && bash prepare.sh
	@echo " > Done..."

.PHONY: testbuild
testbuild: GOPATH = testbuild/src/build
testbuild: GOFLAGS = "-buildmode=pie -trimpath -mod=readonly -modcacherw"
testbuild: testbuild/src
	@echo " > Building CoreDNS with ipdestinationguard plugin (this folder)..."
	@rm -f testbuild/coredns
	@cd testbuild/src/coredns && make coredns
	@mv testbuild/src/coredns/coredns testbuild/coredns
	@echo " > Done..."

# Build CoreDNS with this plugin (generic build)
.PHONY: genericbuild
genericbuild:
	@echo "Building CoreDNS with ipdestinationguard plugin (generic)..."
	@cd genericbuild && bash build.sh
	@echo "Build complete! Binary should be in genericbuild/coredns/"

# Build Arch Linux package
.PHONY: archlinux
archlinux:
	@echo "Building Arch Linux package..."
	@cd archlinux && makepkg
	@echo "Package built! Check archlinux/ directory for .pkg.tar.zst file"

.PHONY: help
help: Makefile
	@echo
	@echo "Choose a command run in "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo

$(DISTPATH)/$(PROJECTNAME): $(GOFILES) go.mod go.sum
	@echo " > Building binary..."
	@mkdir -p $(DISTPATH)
	@go build -mod=vendor -ldflags '-s' -o ./$(DISTPATH)/$(PROJECTNAME) .
	@echo " > Done... available at $(DISTPATH)/$(PROJECTNAME)"

$(DISTPATH)/$(PROJECTNAME).arm64: $(GOFILES) go.mod go.sum
	@echo " > Building binary..."
	@mkdir -p $(DISTPATH)
	@GOARCH=arm64 go build -mod=vendor -ldflags '-s' -o ./$(DISTPATH)/$(PROJECTNAME).arm64 .
	@echo " > Done... available at $(DISTPATH)/$(PROJECTNAME).arm64"
