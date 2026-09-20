BIN_DIR := bin
BINARY := $(BIN_DIR)/enigma

.PHONY: build

build:
	mkdir -p $(BIN_DIR)
	go build -o $(BINARY) ./cmd/enigma

test:
	go test -v ./...