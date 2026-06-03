#!/bin/bash
set -e

KERNEL_VER=$(uname -r)
echo "======================================"
echo " PROBING KERNEL: $KERNEL_VER"
echo "======================================"

# Determine OS
if [ -f /etc/debian_version ]; then
    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get update -qq
    sudo apt-get install -y -qq clang llvm libbpf-dev make golang-go bpftool linux-tools-common linux-tools-generic >/dev/null 2>&1 || true
elif [ -f /etc/redhat-release ]; then
    sudo dnf install -y clang llvm libbpf-devel make golang bpftool >/dev/null 2>&1 || true
fi

echo "[*] Cleaning and building BPF objects..."
make clean >/dev/null 2>&1 || true
export BPF_CLANG=clang
export BPF_CFLAGS="-O2 -g -Wall -Werror"

# Build BPF objects only via go generate
go generate ./src/user/... > bpf_build.log 2>&1
if [ $? -ne 0 ]; then
    echo "❌ BPF Compilation Failed. Missing kernel headers or incompatible clang?"
    cat bpf_build.log
    exit 0
fi

echo "[*] BPF Compiled successfully."

# Build a small dry-run tool to capture verifier output
cat << 'EOF' > dry_run.go
package main
import (
	"fmt"
	"os"
	"github.com/cilium/ebpf"
)
func main() {
	spec, err := ebpf.LoadCollectionSpec("src/user/bpf_bpfel.o")
	if err != nil {
		fmt.Printf("LOAD_ERROR: %v\n", err)
		os.Exit(1)
	}
	
	// Test HW metadata program (Requires 6.1+)
	hwSpec := spec.Copy()
	delete(hwSpec.Programs, "hyperion_filter_generic")
	_, err = ebpf.NewCollectionWithOptions(hwSpec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction},
	})
	if err != nil {
		fmt.Printf("HW_VERIFIER_REJECTED\n")
	} else {
		fmt.Printf("HW_VERIFIER_ACCEPTED\n")
	}

	// Test Generic fallback program
	genSpec := spec.Copy()
	delete(genSpec.Programs, "hyperion_filter_hw")
	_, err = ebpf.NewCollectionWithOptions(genSpec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction},
	})
	if err != nil {
		fmt.Printf("GENERIC_VERIFIER_REJECTED\n")
	} else {
		fmt.Printf("GENERIC_VERIFIER_ACCEPTED\n")
	}
}
EOF

go mod tidy >/dev/null 2>&1
echo "[*] Running Verifier Probes..."
sudo -E go run dry_run.go

echo "======================================"
echo " PROBE COMPLETE"
echo "======================================"
