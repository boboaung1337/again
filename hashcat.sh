#!/bin/bash
export LLVM_VERSION=21
sudo apt update
sudo apt install -y python3-dev libpython3-dev build-essential ocl-icd-libopencl1 cmake git pkg-config libclang-${LLVM_VERSION}-dev clang-${LLVM_VERSION} llvm-${LLVM_VERSION} make ninja-build ocl-icd-dev ocl-icd-opencl-dev libhwloc-dev zlib1g zlib1g-dev clinfo dialog apt-utils libxml2-dev libclang-cpp${LLVM_VERSION}-dev llvm-${LLVM_VERSION}-dev
sudo apt remove -y mesa-opencl-icd 2>/dev/null || true
cd /tmp && rm -rf pocl
git clone https://github.com/pocl/pocl.git && cd pocl
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr -DENABLE_ICD=ON -DENABLE_LLVM=ON -DWITH_LLVM_CONFIG=/usr/bin/llvm-config-21 -DENABLE_LOADABLE_DRIVERS=OFF -DENABLE_HOST_CPU_DEVICES=ON -DKERNELLIB_HOST_CPU_VARIANTS=distro -DENABLE_TESTS=OFF -DENABLE_EXAMPLES=OFF -DSTATIC_LLVM=OFF ..
make -j$(nproc)
sudo make install
sudo ldconfig
clinfo
hashcat -I
hashcat -b -m 0
