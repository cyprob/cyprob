SRCS = $(shell git ls-files '*.go' | grep -v '^vendor/')

BIN_NAME=cyprob
TAG_NAME := $(shell git describe --abbrev=0 --tags --exact-match 2>/dev/null || echo "unknown")
COMMIT := $(shell git rev-parse HEAD)
VERSION_GIT := $(if $(TAG_NAME),$(TAG_NAME),$(SHA))
VERSION := $(if $(VERSION),$(VERSION),$(VERSION_GIT))
DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Default build target
GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

LINT_EXECUTABLES = misspell shellcheck

.PHONY: p ps

p: CLI_EXEC=cyprob
ps: CLI_EXEC=cyprob-server

p ps:
	@CYPROB_CLI_EXECUTABLE=$(CLI_EXEC) go run ./cmd/main.go $(word 2,$(MAKECMDGOALS))

# Parametreler hata vermesin diye
%:
	@:	

.PHONY: default
#? default: Run `make generate` and `make binary`
default: generate binary

.PHONY: test
#? test: Run the unit tests
test: test-unit

.PHONY: test-unit
#? test-unit: Run the unit tests (excludes integration tests)
test-unit:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go test -cover "-coverprofile=cover.out" -v $(TESTFLAGS) ./pkg/... ./cmd/...

.PHONY: test-integration
#? test-integration: Run integration tests only (*_integration_test.go files)
test-integration:
	@echo "🔍 Finding integration test files..."
	@files=$$(find ./pkg ./cmd -name '*_integration_test.go' 2>/dev/null | sed 's|/[^/]*$$||' | sort -u); \
	if [ -n "$$files" ]; then \
		echo "📦 Running integration tests in: $$files"; \
		GOOS=$(GOOS) GOARCH=$(GOARCH) go test -tags=integration -v $(TESTFLAGS) $$files; \
	else \
		echo "⚠️  No integration tests found (*_integration_test.go)"; \
	fi

.PHONY: test-all
#? test-all: Run all tests (unit + integration)
test-all: test-unit test-integration	

.PHONY: fmt
#? fmt: Format the Code
fmt:
	@echo "🔧 Running gci (import organization)..."
	@gci write --skip-generated -s standard -s default -s "prefix(github.com/cyprob/cyprob)" $(SRCS)
	@echo "🔧 Running gofumpt (code formatting)..."
	@gofumpt -l -w -extra $(SRCS)
	@echo "✅ Code formatted"	

#? dist: Create the "dist" directory
dist:
	mkdir -p dist

.PHONY: install-ui-deps
#? install-ui-deps: Install UI dependencies
install-ui-deps:
	cd ui && pnpm install

.PHONY: build-ui
#? build-ui: Build UI for production (outputs to pkg/ui/dist)
build-ui: install-ui-deps
	cd ui && pnpm run build
	@echo "✅ UI built successfully → pkg/ui/dist"

.PHONY: dev-ui
#? dev-ui: Start UI development server (with API proxy to :8080)
dev-ui:
	cd ui && pnpm run dev

.PHONY: clean-ui
#? clean-ui: Clean UI build artifacts
clean-ui:
	rm -rf pkg/ui/dist
	rm -rf ui/dist
	@echo "✅ UI build artifacts cleaned"	

.PHONY: generate
#? generate: Generate code (Dynamic and Static configuration documentation reference files)
generate:
#	go generate

.PHONY: binary
#? binary: Build the binary with embedded UI
binary: build-ui generate dist
	@echo "🔨 Building binary with embedded UI..."
	@echo "Version: $(VERSION) | Commit: $(COMMIT) | Date: $(DATE)"
	CGO_ENABLED=0 GOGC=off GOOS=${GOOS} GOARCH=${GOARCH} go build ${FLAGS[*]} -ldflags "-s -w \
    -X github.com/cyprob/cyprob/pkg/version.version=$(VERSION) \
    -X github.com/cyprob/cyprob/pkg/version.commit=$(COMMIT) \
    -X github.com/cyprob/cyprob/pkg/version.buildDate=$(DATE)" \
    -installsuffix nocgo -o "./dist/${GOOS}/${GOARCH}/$(BIN_NAME)" ./cmd
	@echo "✅ Binary built → ./dist/${GOOS}/${GOARCH}/$(BIN_NAME)"

.PHONY: lint
#? lint: Run golangci-lint
lint:
	golangci-lint run

.PHONY: validate-files
#? validate-files: Validate code and docs
validate-files:
	$(foreach exec,$(LINT_EXECUTABLES),\
            $(if $(shell which $(exec)),,$(error "No $(exec) in PATH")))
	$(CURDIR)/scripts/validate-vendor.sh
	$(CURDIR)/scripts/validate-misspell.sh
	$(CURDIR)/scripts/validate-shell-script.sh

.PHONY: validate
#? validate: Validate code, docs, and vendor
validate: lint validate-files

.PHONY: help
#? help: Get more info on make commands
help: Makefile
	@echo " Choose a command run in cyprob:"
	@sed -n 's/^#?//p' $< | column -t -s ':' |  sort | sed -e 's/^/ /'
