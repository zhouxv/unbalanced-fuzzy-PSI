
## Environment

This code and following instructions are tested on Ubuntu 22.04, with `g++ 13.1.0, CMake 3.22, GNU Make 4.2.1`.

### Install dependencies and build

```bash
##############################

sudo apt-get install libgmp-devlibtool nasm libssl-dev libmpfr-dev libfmt-dev libspdlog-dev 

##############################
# install libOTe
git clone https://github.com/osu-crypto/libOTe.git
cd libOTe
python3 build.py --all --boost --sodium --relic
sudo python3 build.py --install=../../out/install/
cd ..

##############################
# install pailliercryptolib
git clone https://github.com/intel/pailliercryptolib.git
cd pailliercryptolib/
export IPCL_ROOT=$(pwd)
sudo cmake -S . -B build -DCMAKE_INSTALL_PREFIX=../../out/install/ -DCMAKE_BUILD_TYPE=Release -DIPCL_TEST=OFF -DIPCL_BENCHMARK=OFF
sudo cmake --build build -j
sudo cmake --build build --target install -j
cd ..


##############################
git clone https://github.com/BLAKE3-team/BLAKE3.git
cd BLAKE3
git checkout c7f0d216e6fc834b742456b39546c9835baa1277
    
printf "################## Building BLAKE3             ###################\n\n"
cmake -S c -B c/build -DCMAKE_INSTALL_PREFIX=/home/out/install

printf "################## Installing BLAKE3           ###################\n\n"
cmake --build c/build --target install
cd ..

##############################
# build FPSI
mkdir build && cd build
cmake ..
make -j
```
