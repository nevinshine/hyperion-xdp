# Hyperion Build System (M2)

# Compiler & Flags
CLANG = clang
CFLAGS = -O2 -g -Wall -target bpf -c

# Directories
SRC_DIR = src/kern
BIN_DIR = bin

# --- FIXED: Matches your actual file name ---
TARGET = $(BIN_DIR)/hyperion_core.o
SOURCE = $(SRC_DIR)/hyperion_core.c
# --------------------------------------------

# Build Rules
all: $(TARGET)

$(TARGET): $(SOURCE)
	@echo "  [BPF] Compiling Hyperion M2 (Stateful)..."
	@mkdir -p $(BIN_DIR)
	$(CLANG) $(CFLAGS) -o $@ $<
	@echo "  [OK] Build Complete: $@"

clean:
	rm -rf $(BIN_DIR)

# Utility: Load the XDP program
load: $(TARGET)
	@echo "  [NET] Attaching to Loopback (lo)..."
	sudo ip link set dev lo xdp obj $(TARGET) sec xdp verbose

# Utility: Unload the XDP program
unload:
	@echo "  [NET] Detaching from Loopback..."
	sudo ip link set dev lo xdp off

# Utility: View the Kernel Trace Pipe
logs:
	@echo "  [LOG] Reading /sys/kernel/debug/tracing/trace_pipe..."
	sudo cat /sys/kernel/debug/tracing/trace_pipe
