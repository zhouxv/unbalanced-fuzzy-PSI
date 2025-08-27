// authors: Xiang Liu, Yuanchao Luo, Longxin Wang
#pragma once
#include <vector>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/SodiumCurve.h>
#include <ipcl/bignum.h>

#include "config.h"

#ifndef CRYPTOTOOLS_RBOKVS_H
#define CRYPTOTOOLS_RBOKVS_H

using element = oc::block;

struct MatrixRow {
  u64 startPos;
  std::unique_ptr<block[]> data;
  block val;
  u64 next;
};

struct MatrixRow_LongValue {
  u64 startPos;
  std::unique_ptr<block[]> data;
  std::vector<block> val;
  u64 next;
};

struct MatrixRow_rist {
  u64 start_position;
  u64 piv;
  std::unique_ptr<Rist25519_number[]> data;
  std::vector<Rist25519_number> val;
};

enum EncodeStatus { SUCCESS, FAIL, ALLZERO };

struct RBOKVSParam {
  u64 mNumRows;
  // numCols = mScaler * numRows
  double mScaler;
  // statistical security parameter
  u64 mStasSecParam;
  // width of band
  u64 mBandWidth;
  // randomness of hash function
  block mR1, mR2;
  // random seed for encode
  block mSeed;

  u64 numCols() const { return static_cast<u64>(mScaler * mNumRows); }
};

// value 为 block 的 okvs
class RBOKVS {
public:
  // number of elements(rows)
  u64 mN;
  // number of columns
  u64 mSize;
  // width of band
  u64 mW;
  // statistical security parameter
  u64 mSsp;
  // randomness of hash function
  block mRPos, mRBand;
  // PRNG for encode
  PRNG mPrng;
  // hash function
  // blake3_hasher mHasher;
  Timer mTimer;

  RBOKVS() = default;
  RBOKVS(const RBOKVS &copy) {}

  ~RBOKVS() = default;

  void init(const u64 &n, const double &epsilon, const u64 &stasSecParam,
            const block &seed);
  void init(const RBOKVSParam &param);

  RBOKVSParam getParams(const u64 &n, const double &epsilon,
                        const u64 &stasSecParam, const block &seed);

  // generate the randomness of hash function
  void setSeed(const block &seed);

  // get the start position of the band
  u64 hashPos(const block &input);
  // get a random band(w bits)
  void hashBand(const block &input, block *output);

  EncodeStatus reformalize(MatrixRow &row);
  EncodeStatus reformalize(MatrixRow_LongValue &row,
                           const u64 VALUE_LENGTH_IN_BLOCK);

  EncodeStatus insert(u64 *bitToRowMap, MatrixRow *rows, u64 rowIdx);
  EncodeStatus insert(u64 *bitToRowMap, MatrixRow_LongValue *rows, u64 rowIdx,
                      const u64 VALUE_LENGTH_IN_BLOCK);

  EncodeStatus encode(const block *keys, const block *vals, block *output);

  // output
  EncodeStatus encode(const std::vector<block> &keys,
                      const std::vector<std::vector<block>> &vals,
                      const u64 &VALUE_LENGTH_IN_BLOCK,
                      std::vector<std::vector<block>> &output);

  block decode(const block *codeWords, const block &key);
  std::vector<block> decode(const std::vector<std::vector<block>> &codeWords,
                            const block &key, const u64 &VALUE_LENGTH_IN_BLOCK);

  void decode(const block *codeWords, const block *keys, u64 size,
              block *output, u64 numThreads);
};

// value 为 Rist25519_number 的 okvs
class RBOKVS_rist {
public:
  // number of elements(rows)
  u64 num_element;
  // number of columns
  u64 num_columns;
  // width of band
  u64 width_band;
  // statistical security parameter
  u64 lambda;
  // randomness of hash function
  // block mRPos, mRBand;
  block rand_position, rand_band;
  // PRNG for encode
  PRNG okvs_prng;

  RBOKVS_rist() = default;
  RBOKVS_rist(const RBOKVS_rist &copy) {}
  ~RBOKVS_rist() = default;

  void init(const u64 &n, const double &epsilon, const u64 &stasSecParam,
            const block &seed);

  // get the start position of the band
  u64 hash_to_position(const block &input);
  // get a random band(w rist_number)
  void hash_to_band(const block &input, Rist25519_number *output);

  // output
  EncodeStatus encode(const std::vector<block> &keys,
                      const std::vector<std::vector<Rist25519_number>> &vals,
                      const u64 &VALUE_LENGTH_IN_NUMBER,
                      std::vector<std::vector<Rist25519_point>> &output,
                      const Rist25519_point &OKVS_RISTRETTO_BASEPOINT);
  EncodeStatus encode(const std::vector<block> &keys,
                      const std::vector<std::vector<Rist25519_number>> &vals,
                      const u64 &VALUE_LENGTH_IN_NUMBER,
                      std::vector<std::vector<Rist25519_point>> &output);
  EncodeStatus encode(const std::vector<block> &keys,
                      const std::vector<std::vector<Rist25519_number>> &vals,
                      const u64 &VALUE_LENGTH_IN_NUMBER,
                      std::vector<std::vector<Rist25519_number>> &output);

  std::vector<Rist25519_point>
  decode(const std::vector<std::vector<Rist25519_point>> &codeWords,
         const block &key, const u64 &VALUE_LENGTH_IN_NUMBER);

  EncodeStatus
  test_encode(const std::vector<block> &keys,
              const std::vector<std::vector<Rist25519_number>> &vals,
              const u64 &VALUE_LENGTH_IN_NUMBER,
              std::vector<std::vector<Rist25519_number>> &output);

  std::vector<Rist25519_number>
  test_decode(const std::vector<std::vector<Rist25519_number>> &codeWords,
              const block &key, const u64 &VALUE_LENGTH_IN_NUMBER);
};

void print_u8(u8 *buffer, u64 length);
void print_u32(u32 *buffer, u64 length);
void print_number(const Rist25519_number &n);

void print_point(Rist25519_point P);
void print_point(Sodium::Ed25519 P);
void print_vec_point(std::vector<Rist25519_point> P);

void print_element(element e);

void print_vector(std::vector<element> vec);
void print_vector(std::vector<u32> vec);

void print_row_data(osuCrypto::block *data, u64 wBlocks);

void print_row_of_matrix(MatrixRow &a, u64 wBlocks);

void print_row_of_matrix_long_value(MatrixRow_LongValue &a, u64 wBlocks);
void print_row_of_matrix_rist(MatrixRow_rist &a, u64 band_width);

void print_grid(const std::vector<u64> &grid);

std::vector<block> bignumer_to_block_vector(const BigNumber &bn);
BigNumber block_vector_to_bignumer(const std::vector<block> &ct);

std::vector<block> bignumers_to_block_vector(const std::vector<BigNumber> &bn);
std::vector<BigNumber>
block_vector_to_bignumers(const std::vector<block> &ct, const u64 &value_size,
                          std::shared_ptr<BigNumber> nsq);

#endif