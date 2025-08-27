#pragma once

#include <map>
#include <vector>

#include <blake3.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/SodiumCurve.h>
#include <ipcl/bignum.h>
#include <spdlog/spdlog.h>

#include "config.h"

typedef std::chrono::high_resolution_clock::time_point tVar;
#define tNow() std::chrono::high_resolution_clock::now()
#define tStart(t) t = tNow()
#define tEnd(t)                                                                \
  std::chrono::duration_cast<std::chrono::milliseconds>(tNow() - t).count()

class simpleTimer {
public:
  std::mutex mtx;
  tVar t;
  std::map<string, double> timers;
  std::vector<string> timer_keys;

  simpleTimer() {}

  void start() { tStart(t); }
  void end(string msg) {
    timer_keys.push_back(msg);
    timers[msg] = tEnd(t);
  }

  void print() {
    for (const string &key : timer_keys) {
      spdlog::info("{}: {} ms; {} s", key, timers[key], timers[key] / 1000);
    }
  }

  double get_by_key(const string &key) { return timers.at(key); }

  void merge(simpleTimer &other) {
    std::lock_guard<std::mutex> lock(mtx);
    std::lock_guard<std::mutex> other_lock(other.mtx);

    auto other_keys = other.timer_keys;
    auto other_maps = other.timers;

    timer_keys.insert(timer_keys.end(), other_keys.begin(), other_keys.end());
    timers.insert(other_maps.begin(), other_maps.end());
  }

  void clear() {
    timers.clear();
    timer_keys.clear();
  }
};

void sample_points(u64 dim, u64 delta, u64 sender_size, u64 recv_size,
                   u64 intersection_size, vector<pt> &sender_pts,
                   vector<pt> &recv_pts, bool sample_flag);

pt cell(const pt &p, u64 dim, u64 side_len);
pt block_(const pt &p, u64 dim, u64 delta, u64 sidelen);

u64 l_inf_dist(const pt &p1, const pt &p2, u64 dim);

u64 get_position(const pt &cross_point, const pt &source_point, u64 dim);
vector<pt> intersection(const pt &p, u64 dim, u64 delta, bool sigma);

std::vector<block> bignumer_to_block_vector(const BigNumber &bn);
BigNumber block_vector_to_bignumer(const std::vector<block> &ct);
std::vector<block> bignumers_to_block_vector(const std::vector<BigNumber> &bns);

std::vector<BigNumber>
block_vector_to_bignumers(const std::vector<block> &ct, const u64 &value_size,
                          std::shared_ptr<BigNumber> nsq);
std::vector<BigNumber> block_vector_to_bignumers(const std::vector<block> &ct,
                                                 const u64 &value_size);
std::vector<block>
flattenBlocks(const std::vector<std::vector<block>> &blockData);
std::vector<std::vector<block>>
chunkFixedSizeBlocks(const std::vector<block> &flatData, size_t chunk_size);
std::vector<std::vector<block>>
bignumers_to_blocks_vector(const std::vector<BigNumber> &bns);

inline void padding_keys(vector<block> &keys, u64 count) {
  if (keys.size() >= count) {
    return;
  }

  PRNG prng((block(oc::sysRandomSeed())));

  while (keys.size() < count) {
    keys.push_back(prng.get<block>());
  }
}

inline void padding_values(vector<vector<block>> &values, u64 count,
                           u64 blk_size) {
  if (values.size() >= count) {
    return;
  }

  PRNG prng((block(oc::sysRandomSeed())));

  vector<block> blks(blk_size, ZeroBlock);

  while (values.size() < count) {
    prng.get(blks.data(), blk_size);
    values.push_back(blks);
  }
}

inline void padding_bignumers(vector<BigNumber> &nums, u64 count,
                              u64 blk_size) {
  if (nums.size() >= count) {
    return;
  }

  PRNG prng((block(oc::sysRandomSeed())));
  vector<block> blks(blk_size, ZeroBlock);

  while (nums.size() < count) {
    prng.get(blks.data(), blk_size);
    nums.push_back(block_vector_to_bignumer(blks));
  }
}

inline void padding_vec_8(vector<u64> &vec) {
  auto size = vec.size();
  auto remainder = size % 8;
  if (remainder != 0) {
    auto padding_num = 8 - remainder;
    for (u64 i = 0; i < padding_num; i++) {
      vec.push_back(0);
    }
  }
}

struct Monty25519Hash {
  std::size_t operator()(const osuCrypto::Sodium::Monty25519 &point) const {
    std::array<u8, 32> bytes;
    point.toBytes(bytes.data());
    return std::hash<std::string_view>()(
        std::string_view(reinterpret_cast<const char *>(bytes.data()), 32));
  }
};

inline block get_key_from_sum_dim(const block &blk, const u64 dim) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, blk.data(), 16);
  blake3_hasher_update(&hasher, &dim, sizeof(dim));

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline block get_key_from_sum_dim_x(const block &blk, const u64 dim,
                                    const u64 x) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, blk.data(), 16);
  blake3_hasher_update(&hasher, &dim, sizeof(dim));
  blake3_hasher_update(&hasher, &x, sizeof(x));

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline block get_key_from_pt_dim(const u64 val, const u64 dim) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, &val, sizeof(val));
  blake3_hasher_update(&hasher, &dim, sizeof(dim));

  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline block get_key_from_point(const vector<u64> &point) {
  blake3_hasher hasher;
  block hash_out;
  blake3_hasher_init(&hasher);
  for (auto pt : point) {
    blake3_hasher_update(&hasher, &pt, sizeof(pt));
  }
  blake3_hasher_finalize(&hasher, hash_out.data(), 16);

  return hash_out;
}

inline u64 combination(u64 n, u64 k) {
  if (k > n)
    return 0;
  if (k > n - k)
    k = n - k; // C(n, k) == C(n, n-k)
  u64 result = 1;
  for (u64 i = 0; i < k; ++i) {
    result = result * (n - i) / (i + 1);
  }
  return result;
}

inline u64 fast_pow(u64 base, u64 exp) {
  u64 result = 1;
  while (exp > 0) {
    if (exp & 1)
      result *= base;
    base *= base;
    exp >>= 1;
  }
  return result;
}
