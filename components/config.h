#pragma once
#include <cryptoTools/Crypto/SodiumCurve.h>

using namespace oc;
using namespace std;

//  DH PSICA
using DH25519_point = osuCrypto::Sodium::Monty25519;
using DH25519_number = osuCrypto::Sodium::Scalar25519;

using pt = vector<u64>;

const u64 OKVS_LAMBDA = 40;
const double OKVS_EPSILON = 0.1;
const block OKVS_SEED = oc::block(6800382592637124185);

using Rist25519_point = osuCrypto::Sodium::Rist25519;
using Rist25519_number = osuCrypto::Sodium::Prime25519;

const size_t POINT_LENGTH_IN_BYTE = sizeof(Rist25519_point);
using Rist25519_point_in_bytes = std::array<oc::u8, POINT_LENGTH_IN_BYTE>;

const oc::u64 EC_CIPHER_SIZE_IN_NUMBER = 2;
const Rist25519_point dash(oc::block(70));
const Rist25519_point ZERO_POINT(dash - dash);

const oc::u32 PAILLIER_KEY_SIZE_IN_BIT = 2048;
const oc::u32 PAILLIER_CIPHER_SIZE_IN_BLOCK =
    ((PAILLIER_KEY_SIZE_IN_BIT * 2) / 128);
const oc::u32 PAILLIER_CIPHER_SIZE_IN_BYTE = PAILLIER_CIPHER_SIZE_IN_BLOCK * 16;

const u64 COM_CHUNK_SIZE = 100000000;