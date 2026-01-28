CLANG ?= clang
GO ?= go
BIN_DIR := bin
BIN_NAME := hyperion_ctrl

export BPF_CLANG := $(CLANG)
export BPF_CFLAGS := -O2 -g -Wall -Werror

.PHONY: all clean build run

all: build

build:
	@mkdir -p $(BIN_DIR)
	@echo "  [BPF] Generating Artifacts..."
	cd src/user && $(GO) generate
	@echo "  [GO] Compiling Controller..."
	$(GO) build -o $(BIN_DIR)/$(BIN_NAME) ./src/user

clean:
	rm -rf $(BIN_DIR)
	rm -f src/user/bpf_*.go src/user/bpf_*.o src/user/xdp_bpf.go src/user/xdp_bpf.o

run: build
	sudo ./$(BIN_DIR)/$(BIN_NAME) -iface lo
