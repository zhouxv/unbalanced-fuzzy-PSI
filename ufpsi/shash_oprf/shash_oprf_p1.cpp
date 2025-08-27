#include <algorithm>
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
#include "shash_oprf_p1.h"
#include "utils/util.h"

void ShashOprfP1::offline_hash() {

  vector<vector<pair<u64, u64>>> intervals(DIM);

  shash_keys.resize(DIM);
  shash_values.resize(DIM);

  vector<block> random_values(PTS_NUM * DIM);
  prng.get(random_values.data(), random_values.size());

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

  for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
    for (u64 i = 0; i < intervals[dim_index].size(); i++) {
      for (u64 j = intervals[dim_index][i].first;
           j <= intervals[dim_index][i].second; j++) {
        shash_keys[dim_index].push_back(j);
        shash_values[dim_index].push_back(
            random_values[dim_index * PTS_NUM + i]);
      }
    }
  }

  auto compare_lambda = [](const pair<u64, u64> &a, u64 value) {
    return a.second < value;
  };

  H1_sums.resize(PTS_NUM, ZeroBlock);

  u64 pt_index = 0;

  for (const auto &point : pts) {
    for (u64 dim_index = 0; dim_index < DIM; dim_index++) {
      auto it = std::lower_bound(intervals[dim_index].begin(),
                                 intervals[dim_index].end(), point[dim_index],
                                 compare_lambda);

      if (it != intervals[dim_index].end() && it->first <= point[dim_index]) {
        auto j = distance(intervals[dim_index].begin(), it);
        H1_sums[pt_index] ^= random_values[dim_index * PTS_NUM + j];
      } else {
        throw runtime_error("P1 getID random error");
      }
    }
    pt_index += 1;
  }

  shash_keys_blocks.resize(DIM);
  // shash key || dim
  for (u64 i = 0; i < DIM; i++) {
    for (auto key : shash_keys[i]) {
      shash_keys_blocks[i].push_back(block(key, i));
    }
  }
}

void ShashOprfP1::online_hash() {
  // PSV sender offline
  vector<block> psv_r(DIM);
  prng.get<block>(psv_r.data(), psv_r.size());

  block temp(ZeroBlock);
  for (u64 i = 0; i < DIM - 1; i++) {
    temp = psv_r[i] ^ temp;
  }
  psv_r[DIM - 1] = temp;

  /// PSV sender Step 1
  volePSI::RsOprfSender oprfSender;
  coproto::sync_wait(oprfSender.send(OTHER_PTS_NUM * DIM, prng, sockets[0]));

  /// PSV sender Step 2
  vector<vector<block>> okvr_keys(DIM);
  for (u64 i = 0; i < DIM; i++) {
    for (auto key : shash_keys[i]) {
      okvr_keys[i].push_back(block(key, i));
    }
  }

  vector<vector<block>> oprf_eval_values(DIM);

  for (u64 i = 0; i < DIM; i++) {
    oprf_eval_values[i].resize(shash_keys_blocks[i].size());
    oprfSender.eval(shash_keys_blocks[i], oprf_eval_values[i]);
  }

  vector<vector<block>> okvr_values(DIM);
  for (u64 i = 0; i < DIM; i++) {
    for (u64 j = 0; j < shash_values[i].size(); j++) {
      okvr_values[i].push_back(shash_values[i][j] ^ psv_r[i] ^
                               oprf_eval_values[i][j]);
    }
  }

  for (u64 i = 0; i < DIM; i++) {
    padding_keys(okvr_values[i], PTS_NUM * (2 * DELTA + 1));
    padding_keys(okvr_keys[i], PTS_NUM * (2 * DELTA + 1));
  }

  vector<RBOKVS> rb_okvs_vec;
  rb_okvs_vec.resize(DIM);
  for (u64 i = 0; i < DIM; i++) {
    rb_okvs_vec[i].init(PTS_NUM * (2 * DELTA + 1), OKVS_EPSILON, OKVS_LAMBDA,
                        OKVS_SEED);
  }

  // encode
  auto okvr_size = rb_okvs_vec[0].mSize;
  vector<vector<block>> encodings(DIM, vector<block>(okvr_size, ZeroBlock));

  for (u64 i = 0; i < DIM; i++) {
    rb_okvs_vec[i].encode(okvr_keys[i].data(), okvr_values[i].data(),
                          encodings[i].data());
  }

  auto tmp_com = sockets[0].mImpl->mBytesSent;
  coproto::sync_wait(sockets[0].send(okvr_size));
  coproto::sync_wait(sockets[0].flush());
  for (u64 i = 0; i < DIM; i++) {
    coproto::sync_wait(sockets[0].send(encodings[i]));
  }
  coproto::sync_wait(sockets[0].flush());

  shash_keys.clear();
  shash_keys_blocks.clear();
  shash_values.clear();
  shash_keys.shrink_to_fit();
  shash_keys_blocks.shrink_to_fit();
  shash_values.shrink_to_fit();
}
