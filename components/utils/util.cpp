#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <vector>

#include "utils/util.h"

void sample_points(u64 dim, u64 delta, u64 send_size, u64 recv_size,
                   u64 intersection_size, vector<pt> &send_pts,
                   vector<pt> &recv_pts, bool sample_flag) {
  PRNG prng(oc::sysRandomSeed());

  for (u64 i = 0; i < send_size; i++) {
    for (u64 j = 0; j < dim; j++) {
      send_pts[i][j] =
          (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) + 2 * delta;
    }
  }
  if (sample_flag) {

    for (u64 i = 0; i < recv_size; i++) {
      for (u64 j = 0; j < dim; j++) {
        recv_pts[i][j] = send_pts[i][j];
      }
    }

  } else {
    for (u64 i = 0; i < recv_size; i++) {
      for (u64 j = 0; j < dim; j++) {
        recv_pts[i][j] =
            (prng.get<u64>()) % ((0xffff'ffff'ffff'ffff) - 3 * delta) +
            1.5 * delta;
      }
    }

    u64 base_pos = (prng.get<u64>()) % (send_size - intersection_size - 1);
    // u64 base_pos = 0;
    for (u64 i = base_pos; i < base_pos + intersection_size; i++) {
      for (u64 j = 0; j < dim; j++) {
        send_pts[i][j] = recv_pts[i - base_pos][j];
      }
      for (u64 j = 0; j < 1; j++) {
        send_pts[i][j] += ((i8)((prng.get<u8>()) % (delta - 1)) - delta / 2);
      }
    }
  }
}

pt cell(const pt &p, u64 dim, u64 side_len) {
  pt bot_left_corner(dim, 0);
  for (u64 i = 0; i < dim; ++i) {
    bot_left_corner[i] = p[i] / side_len;
  }
  return bot_left_corner;
}

pt block_(const pt &p, u64 dim, u64 delta, u64 sidelen) {
  pt min(dim, 0);
  for (u64 i = 0; i < dim; ++i) {

    min[i] = p[i] - delta;
  }
  return cell(min, dim, sidelen);
}

u64 l_inf_dist(const pt &p1, const pt &p2, u64 dim) {
  u64 max_diff = 0;
  for (u64 i = 0; i < dim; ++i) {
    u64 diff = (p1[i] > p2[i]) ? (p1[i] - p2[i]) : (p2[i] - p1[i]);
    max_diff = std::max(max_diff, diff);
  }
  return max_diff;
}

u64 get_position(const pt &cross_point, const pt &source_point, u64 dim) {
  u64 pos = 0;
  for (u64 i = 0; i < dim; ++i) {
    if (cross_point[i] > source_point[i]) {
      pos += 1ULL << i;
    }
  }
  return pos;
}

vector<pt> intersection(const pt &p, u64 dim, u64 delta, bool sigma) {
  u64 side_len = (sigma) ? 4 * delta : delta;
  u64 blk_cells = (sigma) ? (1 << dim) : (std::pow(3, dim));

  vector<pt> results;
  results.reserve(blk_cells);

  pt blk = block_(p, dim, delta, side_len);

  if (sigma) {
    for (u64 i = 0; i < blk_cells; ++i) {
      pt temp(dim, 0);
      for (u64 j = 0; j < dim; ++j) {
        if ((i >> j) & 1) {
          temp[j] = blk[j] + 1;
        } else {
          temp[j] = blk[j];
        }
      }
      results.push_back(temp);
    }
  } else {
    for (u64 i = 0; i < blk_cells; ++i) {
      pt temp(dim, 0);
      u64 remainder = i;
      for (u64 j = 0; j < dim; ++j) {
        u64 digit = remainder % 3;
        remainder /= 3;

        if (digit == 0) {
          temp[j] = blk[j];
        } else if (digit == 1) {
          temp[j] = blk[j] + 1;
        } else { // digit == 2
          temp[j] = blk[j] + 2;
        }
      }
      results.push_back(temp);
    }
  }

  return results;
}

std::vector<block> bignumer_to_block_vector(const BigNumber &bn) {
  std::vector<u32> ct;
  bn.num2vec(ct);

  std::vector<block> cipher_block(PAILLIER_CIPHER_SIZE_IN_BLOCK, ZeroBlock);

  PRNG prng(oc::sysRandomSeed());

  if (ct.size() < PAILLIER_CIPHER_SIZE_IN_BLOCK * 4) {
    for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
      cipher_block[i] = prng.get<block>();
    }
  } else {
    for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
      cipher_block[i] =
          block(((u64(ct[4 * i + 3])) << 32) + (u64(ct[4 * i + 2])),
                ((u64(ct[4 * i + 1])) << 32) + (u64(ct[4 * i])));
    }
  }

  return cipher_block;
}

BigNumber block_vector_to_bignumer(const std::vector<block> &ct) {
  std::vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);
  u32 temp[4];
  for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
    memcpy(temp, ct[i].data(), 16);

    ct_u32[4 * i] = temp[0];
    ct_u32[4 * i + 1] = temp[1];
    ct_u32[4 * i + 2] = temp[2];
    ct_u32[4 * i + 3] = temp[3];
  }
  BigNumber bn = BigNumber(ct_u32.data(), ct_u32.size());
  return bn;
}

std::vector<block>
bignumers_to_block_vector(const std::vector<BigNumber> &bns) {
  auto count = bns.size();
  std::vector<block> cipher_block;
  cipher_block.reserve(PAILLIER_CIPHER_SIZE_IN_BLOCK * count);

  std::vector<u32> ct;
  ct.reserve(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4);

  PRNG prng(oc::sysRandomSeed());

  for (const auto &bn : bns) {
    bn.num2vec(ct);

    if (ct.size() < PAILLIER_CIPHER_SIZE_IN_BLOCK * 4) {
      for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
        cipher_block.push_back(prng.get<block>());
      }
    } else {
      // notes: Little-endian BLock
      for (auto i = 0; i < PAILLIER_CIPHER_SIZE_IN_BLOCK; i++) {
        cipher_block.push_back(
            block(((u64(ct[4 * i + 3])) << 32) + (u64(ct[4 * i + 2])),
                  ((u64(ct[4 * i + 1])) << 32) + (u64(ct[4 * i]))));
      }
    }
    ct.clear();
  }

  return cipher_block;
}

std::vector<BigNumber>
block_vector_to_bignumers(const std::vector<block> &ct, const u64 &value_size,
                          std::shared_ptr<BigNumber> nsq) {
  vector<BigNumber> bns;

  std::vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);

  for (auto i = 0; i < value_size; i++) {
    u32 temp[4];
    u64 index = i * PAILLIER_CIPHER_SIZE_IN_BLOCK;
    for (auto j = 0; j < PAILLIER_CIPHER_SIZE_IN_BLOCK; j++) {
      memcpy(temp, ct[index + j].data(), 16);
      ct_u32[4 * j] = temp[0];
      ct_u32[4 * j + 1] = temp[1];
      ct_u32[4 * j + 2] = temp[2];
      ct_u32[4 * j + 3] = temp[3];
    }

    bns.push_back(BigNumber(ct_u32.data(), ct_u32.size()) % (*nsq));
  }

  return bns;
}

std::vector<BigNumber> block_vector_to_bignumers(const std::vector<block> &ct,
                                                 const u64 &value_size) {
  vector<BigNumber> bns;

  std::vector<uint32_t> ct_u32(PAILLIER_CIPHER_SIZE_IN_BLOCK * 4, 0);

  for (auto i = 0; i < value_size; i++) {
    u32 temp[4];
    u64 index = i * PAILLIER_CIPHER_SIZE_IN_BLOCK;
    for (auto j = 0; j < PAILLIER_CIPHER_SIZE_IN_BLOCK; j++) {
      memcpy(temp, ct[index + j].data(), 16);
      ct_u32[4 * j] = temp[0];
      ct_u32[4 * j + 1] = temp[1];
      ct_u32[4 * j + 2] = temp[2];
      ct_u32[4 * j + 3] = temp[3];
    }

    bns.push_back(BigNumber(ct_u32.data(), ct_u32.size()));
  }

  return bns;
}

std::vector<block>
flattenBlocks(const std::vector<std::vector<block>> &blockData) {

  size_t total_size = 0;
  for (const auto &inner_vec : blockData) {
    total_size += inner_vec.size();
  }

  std::vector<block> result;
  result.reserve(total_size);

  for (const auto &inner_vec : blockData) {
    if (!inner_vec.empty()) {
      // 直接使用内存拷贝，避免逐个push_back
      size_t old_size = result.size();
      result.resize(old_size + inner_vec.size());
      std::memcpy(result.data() + old_size, inner_vec.data(),
                  inner_vec.size() * sizeof(block));
    }
  }

  return result;
}

std::vector<std::vector<block>>
chunkFixedSizeBlocks(const std::vector<block> &flatData, size_t chunk_size) {
  assert(chunk_size > 0 && "Chunk size must be positive");
  assert(flatData.size() % chunk_size == 0 &&
         "Data size must be divisible by chunk size");

  std::vector<std::vector<block>> result;
  result.reserve(flatData.size() / chunk_size);

  for (size_t i = 0; i < flatData.size(); i += chunk_size) {
    result.emplace_back(flatData.begin() + i,
                        flatData.begin() + i + chunk_size);
  }

  return result;
}

std::vector<std::vector<block>>
bignumers_to_blocks_vector(const std::vector<BigNumber> &bns) {
  vector<vector<block>> blks_vector;
  blks_vector.reserve(bns.size());
  for (auto bn : bns) {
    blks_vector.push_back(bignumer_to_block_vector(bn));
  }
  return blks_vector;
}