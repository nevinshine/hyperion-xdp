#!/bin/bash
set -e

BOXES=(
    "generic/ubuntu2204" # Kernel 5.15
    "generic/ubuntu2304" # Kernel 6.2
)

mkdir -p tests/matrix_run
cd tests/matrix_run

# Tar the essential codebase to bypass Vagrant Rsync bugs
echo "[*] Packaging codebase..."
tar -czf /tmp/hyperion.tar.gz -C ../../ src tests Makefile go.mod go.sum
mv /tmp/hyperion.tar.gz .

cat << 'EOF' > ../matrix_results.md
# Empirical Matrix Results

| Vagrant Box | Kernel Version | Generic XDP Fallback | Hardware Metadata kfuncs |
|-------------|----------------|----------------------|--------------------------|
EOF

for BOX in "${BOXES[@]}"; do
    echo "======================================"
    echo " SPINNING UP: $BOX"
    echo "======================================"
    
    cat << EOF > Vagrantfile
Vagrant.configure("2") do |config|
  config.vm.box = "$BOX"
  config.vm.provider :libvirt do |libvirt|
    libvirt.memory = 2048
    libvirt.cpus = 2
  end
  
  # Inject the tarball natively
  config.vm.provision "file", source: "hyperion.tar.gz", destination: "/tmp/hyperion.tar.gz"
  
  # Run the internal probe as a provisioner to bypass SSH timeout parsing bugs
  config.vm.provision "shell", inline: <<-SHELL
    set -e
    mkdir -p /root/hyperion
    tar -xzf /tmp/hyperion.tar.gz -C /root/hyperion
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq clang llvm libbpf-dev make golang-go >/dev/null 2>&1
    cd /root/hyperion
    bash tests/internal_matrix_probe.sh > /tmp/probe_out.log 2>&1
  SHELL
end
EOF

    vagrant up --provider=libvirt
    
    echo "[*] Extracting Probe Results..."
    vagrant ssh -c "cat /tmp/probe_out.log" > probe_out.log 2>/dev/null || true
    
    KERNEL=$(grep "PROBING KERNEL" probe_out.log | awk '{print $4}' | tr -d '\r')
    GENERIC=$(grep "GENERIC_VERIFIER" probe_out.log | awk -F_ '{print $3}' | tr -d '\r')
    HW=$(grep "HW_VERIFIER" probe_out.log | awk -F_ '{print $3}' | tr -d '\r')
    
    if [ -z "$KERNEL" ]; then KERNEL="FAILED_TO_BOOT"; fi
    if [ -z "$GENERIC" ]; then GENERIC="ERROR"; fi
    if [ -z "$HW" ]; then HW="ERROR"; fi
    
    if grep -q "BPF Compilation Failed" probe_out.log; then
        GENERIC="COMPILE_ERR"
        HW="COMPILE_ERR"
    fi
    
    [ "$GENERIC" == "ACCEPTED" ] && GEN_FMT="✅ ACCEPTED" || GEN_FMT="❌ $GENERIC"
    [ "$HW" == "ACCEPTED" ] && HW_FMT="✅ ACCEPTED" || HW_FMT="❌ $HW"
    
    echo "| \`$BOX\` | \`$KERNEL\` | $GEN_FMT | $HW_FMT |" >> ../matrix_results.md
    
    echo "[*] Tearing down VM..."
    vagrant destroy -f
    rm -f Vagrantfile probe_out.log
    
    echo "[*] Pruning base box to save disk space..."
    vagrant box remove "$BOX" --all || true
done

echo "======================================"
echo " MATRIX COMPLETE"
cat ../matrix_results.md
echo "======================================"
