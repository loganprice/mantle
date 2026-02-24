BINARY_NAME := mantle
BUILD_DIR := bin
CMD_DIR := cmd/mantle

.PHONY: build test test-cover lint fmt vet clean docker-build

build:
	@echo "==> Building $(BINARY_NAME)..."
	go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)/

test:
	@echo "==> Running tests..."
	go test -race -count=1 ./...

test-cover:
	@echo "==> Running tests with coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | sort -k 3 -n

lint:
	@echo "==> Running golangci-lint..."
	go tool golangci-lint run

fmt:
	@echo "==> Formatting code..."
	gofmt -w .
	$$(go env GOPATH)/bin/goimports -w .

vet:
	@echo "==> Running go vet..."
	go vet ./...

clean:
	@echo "==> Cleaning..."
	rm -rf $(BUILD_DIR) coverage.out

docker-build:
	@echo "==> Building frontend image..."
	docker build -t mantle:dev .
