wget https://github.com/microsoft/SEAL/archive/refs/tags/v4.1.2.tar.gz
tar -zxvf v4.1.2.tar.gz

cd SEAL-4.1.2

cmake -S . -B build -DCMAKE_INSTALL_PREFIX=../../out/install/linux -DSEAL_DEFAULT_PRNG=Shake256
cmake --build build
cmake --install build