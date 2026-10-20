.PHONY: build test race cover lint fmt vet vuln clean data

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/omni-line/mal-check/internal/version.Version=$(VERSION)

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/mal-check ./cmd/mal-check

test:
	go test ./...

race:
	go test -race -count=1 ./...

# Minimum statement coverage enforced locally and in CI.
# Scoped to ./internal/... so thin cmd/ and scripts/ packages (no tests) do not
# drag the total under the floor on Go 1.22+, which reports them as 0%.
COVER_MIN ?= 80

cover:
	go test -coverprofile=coverage.out ./internal/...
	@total=$$(go tool cover -func=coverage.out | tail -1 | awk '{print $$NF}' | tr -d '%'); \
	echo "total: $${total}% (minimum $(COVER_MIN)%)"; \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { if ((t+0) < (m+0)) { printf "coverage %.1f%% is below %s%%\n", t, m; exit 1 } }'

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed; running go vet only"; go vet ./...; exit 0; }
	golangci-lint run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Refresh the embedded malicious-package snapshot (network: clones upstream).
MP_DIR ?= $(shell mktemp -d)

data:
	git clone --depth 1 --quiet https://github.com/ossf/malicious-packages $(MP_DIR)/malicious-packages
	go run ./scripts/update-data -src $(MP_DIR)/malicious-packages -out internal/maldb

clean:
	rm -rf bin dist coverage.out
