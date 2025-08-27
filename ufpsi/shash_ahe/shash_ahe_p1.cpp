#include <algorithm>
#include <coproto/Common/macoro.h>
#include <format>
#include <ipcl/utils/context.hpp>
#include <iterator>
#include <vector>

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <spdlog/spdlog.h>

#include "config.h"
#include "rb_okvs/rb_okvs.h"
#include "rr22/Oprf.h"
#include "shash_ahe_p1.h"
#include "utils/util.h"

void ShashAheP1::offline(vector<vector<vector<block>>> &shash_encodings) {

  vector<vector<pair<u64, u64>>> intervals(DIM);

  shash_keys.resize(DIM);
  shash_values.resize(DIM);

  vector<u64> random_values(PTS_NUM * DIM);
  vector<BigNumber> random_bns(PTS_NUM * DIM);

  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      random_values[i * DIM + j] = prng.get<u64>() >> DIM;
      random_bns[i * DIM + j] =
          BigNumber(reinterpret_cast<Ipp32u *>(&random_values[i * DIM + j]), 2);
    }
  }

  for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
    vector<pair<u64, u64>> interval;
    interval.reserve(PTS_NUM);

    for (const auto &pt : pts) {
      interval.push_back({pt[dim_index] - DELTA, pt[dim_index] + DELTA});
    }

    std::sort(interval.begin(), interval.end());

    for (auto [start, end] : interval) {
      if (!intervals[dim_index].empty() &&
          start <= intervals[dim_index].back().second) {

        intervals[dim_index].back().second =
            max(intervals[dim_index].back().second, end);
      } else {

        intervals[dim_index].emplace_back(start, end);
      }
    }
  }

  auto compare_lambda = [](const pair<u64, u64> &a, u64 value) {
    return a.second < value;
  };

  H1_sums.resize(PTS_NUM);

  for (u64 pt_index = 0; pt_index < PTS_NUM; pt_index++) {
    for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
      auto it = std::lower_bound(intervals[dim_index].begin(),
                                 intervals[dim_index].end(),
                                 pts[pt_index][dim_index], compare_lambda);

      if (it != intervals[dim_index].end() &&
          it->first <= pts[pt_index][dim_index]) {
        auto j = distance(intervals[dim_index].begin(), it);
        H1_sums[pt_index] += random_values[dim_index * PTS_NUM + j];
      } else {
        throw runtime_error("P1 getID random error");
      }
    }
  }

  // for (u64 i = 0; i < 5; i++) {
  //   std::cout << "i " << i << " " << sums[i] << endl;
  // }

  // ipcl::initializeContext("QAT");
  // ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  // ipcl::PlainText random_plains = ipcl::PlainText(random_bns);
  // ipcl::CipherText pt_ciphers = palliar_pk.encrypt(random_plains);
  // auto random_blks = bignumers_to_blocks_vector(pt_ciphers.getTexts());
  // ipcl::terminateContext();

  // for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
  //   shash_keys[dim_index].reserve(PTS_NUM * (2 * DELTA + 1));
  //   shash_values[dim_index].reserve(PTS_NUM * (2 * DELTA + 1));
  //   for (u64 i = 0; i < intervals[dim_index].size(); i++) {
  //     for (u64 j = intervals[dim_index][i].first;
  //          j <= intervals[dim_index][i].second; j++) {
  //       shash_keys[dim_index].push_back(get_key_from_pt_dim(j, dim_index));
  //       shash_values[dim_index].push_back(random_blks[dim_index * PTS_NUM +
  //       i]);
  //     }
  //   }
  // }

  // for (u64 i = 0; i < DIM; i++) {
  //   padding_keys(shash_keys[i], PTS_NUM * (2 * DELTA + 1));
  //   padding_values(shash_values[i], PTS_NUM * (2 * DELTA + 1),
  //                  PAILLIER_CIPHER_SIZE_IN_BLOCK);
  // }

  // RBOKVS rb_okvs;
  // rb_okvs.init(PTS_NUM * (2 * DELTA + 1), OKVS_EPSILON, OKVS_LAMBDA,
  // OKVS_SEED); auto okvr_mSize = rb_okvs.mSize;

  // shash_encodings.resize(DIM);
  // for (u64 i = 0; i < DIM; i++) {
  //   shash_encodings[i].resize(
  //       rb_okvs.mSize, vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK,
  //       ZeroBlock));
  //   rb_okvs.encode(shash_keys[i], shash_values[i],
  //                  PAILLIER_CIPHER_SIZE_IN_BLOCK, shash_encodings[i]);
  // }

  auto okvr_mN = PTS_NUM * (2 * DELTA + 1);
  RBOKVS rb_okvs_1;
  rb_okvs_1.init(PTS_NUM * (2 * DELTA + 1), OKVS_EPSILON, OKVS_LAMBDA,
                 OKVS_SEED);
  shash_encodings.resize(DIM);
  for (u64 i = 0; i < DIM; i++) {
    shash_encodings[i].resize(
        rb_okvs_1.mSize,
        vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK, ZeroBlock));
    for (auto j = 0; j < rb_okvs_1.mSize; j++) {
      prng.get(shash_encodings[i][j].data(), PAILLIER_CIPHER_SIZE_IN_BLOCK);
    }
  }
}

void ShashAheP1::online(vector<vector<vector<block>>> &shash_encodings) {
  u64 shash_encodings_mN = PTS_NUM * (2 * DELTA + 1);
  RBOKVS rbokvs;
  rbokvs.init(shash_encodings_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  coproto::sync_wait(sockets[0].send(shash_encodings_mN));
  coproto::sync_wait(sockets[0].send(rbokvs.mSize));
  coproto::sync_wait(sockets[0].flush());

  u64 sum_blk_size = OTHER_PTS_NUM * PAILLIER_CIPHER_SIZE_IN_BLOCK;
  vector<block> sums_blks(sum_blk_size);

  coproto::sync_wait(sockets[0].recvResize(sums_blks));
  coproto::sync_wait(sockets[0].flush());

  auto sum_bns = block_vector_to_bignumers(sums_blks, OTHER_PTS_NUM);

  auto sum_cipher = ipcl::CipherText(palliar_pk, sum_bns);

  auto sum_plains = palliar_sk.decrypt(sum_cipher);

  vector<u64> res(OTHER_PTS_NUM);
  for (u64 i = 0; i < OTHER_PTS_NUM; i++) {
    auto tmp = sum_plains.getElementVec(i);
    res[i] = ((u64)tmp[1] << 32) | tmp[0];
  }

  coproto::sync_wait(sockets[0].send(res));
  coproto::sync_wait(sockets[0].flush());
}