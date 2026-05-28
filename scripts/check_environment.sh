#!/bin/bash
echo "=== Table 3.1 Version Check ==="
echo ""
echo "[Host: Lenovo Legion 5i Pro Gen 7, Intel i7-12700H, 32 GB DDR5]"
echo ""
echo "--- Ubuntu ---"
lsb_release -d
echo ""
echo "--- Python ---"
python3 --version
echo ""
echo "--- VS Code ---"
code --version 2>/dev/null | head -1
echo ""
echo "--- Git ---"
git --version
echo ""
echo "--- Ryu (in venv) ---"
source ~/ryu-env/bin/activate && ryu-manager --version 2>&1 | head -1
echo ""
echo "--- Mininet ---"
sudo mn --version 2>&1
echo ""
echo "--- Open vSwitch ---"
sudo ovs-vsctl --version | head -1
echo ""
echo "--- tcpreplay ---"
tcpreplay --version | head -1
echo ""
echo "--- editcap ---"
editcap --version 2>&1 | head -1
echo ""
echo "--- Dataset ---"
ls -lh ~/sdn-thesis/datasets/PCAP-03-11.pcap 2>/dev/null && echo "PCAP present" || echo "PCAP not yet copied"