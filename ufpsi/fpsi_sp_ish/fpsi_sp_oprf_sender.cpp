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
#include "fpsi_sp_oprf_sender.h"
#include "rb_okvs/rb_okvs.h"
#include "rr22/Oprf.h"
#include "utils/util.h"

void PsiSpSenderISH::offline_hash() {

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

void PsiSpSenderISH::online_hash() {
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

void PsiSpSenderISH::setup() {
  u64 okvr_size = PTS_NUM * DIM;
  // note: random gen
  // ipcl::initializeContext("QAT");
  // ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  // vector<BigNumber> enc_bns(okvr_size);

  // for (u64 i = 0; i < PTS_NUM; i++) {
  //   for (u64 j = 0; j < DIM; j++) {
  //     enc_bns[i * DIM + j] =
  //         BigNumber(reinterpret_cast<Ipp32u *>(&pts[i][j]), 2);
  //   }
  // }

  // ipcl::PlainText pt_plains = ipcl::PlainText(enc_bns);
  // ipcl::CipherText pt_ciphers = palliar_pk.encrypt(pt_plains);
  // ipcl::terminateContext();

  // //
  // vector<block> keys(okvr_size);
  // vector<vector<block>> values(okvr_size);
  // for (u64 i = 0; i < PTS_NUM; i++) {
  //   for (u64 j = 0; j < DIM; j++) {
  //     keys[i * DIM + j] = get_key_from_sum_dim(H1_sums[i], j);
  //     values[i * DIM + j] = bignumer_to_block_vector(pt_ciphers[i * DIM +
  //     j]);
  //   }
  // }

  // RBOKVS rb_okvs;
  // rb_okvs.init(okvr_size, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  // setup_encoding.resize(rb_okvs.mSize,
  //                       vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));
  // rb_okvs.encode(keys, values, PAILLIER_CIPHER_SIZE_IN_BLOCK,
  // setup_encoding);

  RBOKVS rb_okvs;
  rb_okvs.init(okvr_size, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  setup_encoding.resize(rb_okvs.mSize,
                        vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));

  for (auto tmp : setup_encoding) {
    prng.get<block>(tmp.data(), PAILLIER_CIPHER_SIZE_IN_BLOCK);
  }

  H1_sums.clear();
  H1_sums.shrink_to_fit();
};

void PsiSpSenderISH::offline() {
  offline_hash();
  setup();
}

void PsiSpSenderISH::online() {
  online_hash();

  u64 setup_mN = PTS_NUM * DIM;
  coproto::sync_wait(sockets[0].send(setup_mN));
  coproto::sync_wait(sockets[0].send(setup_encoding.size()));
  coproto::sync_wait(sockets[0].flush());

  auto flat_blocks = flattenBlocks(setup_encoding);

  auto tmp_com = sockets[0].bytesSent();
  coproto::sync_wait(sockets[0].send(flat_blocks));
  coproto::sync_wait(sockets[0].flush());

  setup_encoding.clear();
  setup_encoding.shrink_to_fit();

  u64 sum_size;
  coproto::sync_wait(sockets[0].recv(sum_size));
  coproto::sync_wait(sockets[0].flush());
  vector<block> sum_blks(sum_size * PAILLIER_CIPHER_SIZE_IN_BLOCK);
  coproto::sync_wait(sockets[0].recvResize(sum_blks));
  coproto::sync_wait(sockets[0].flush());

  auto sum_bns = block_vector_to_bignumers(sum_blks, sum_size);
  auto sum_dec = palliar_sk.decrypt(ipcl::CipherText(palliar_pk, sum_bns));

  vector<u64> sum(sum_size);
  for (u64 i = 0; i < sum_size; i++) {
    auto tmp = sum_dec.getElementVec(i);
    sum[i] = ((u64)tmp[1] << 32) | tmp[0];
  }

  u64 mN_fmatch, mSize_fmatch;
  coproto::sync_wait(sockets[0].recv(mN_fmatch));
  coproto::sync_wait(sockets[0].recv(mSize_fmatch));
  coproto::sync_wait(sockets[0].flush());

  vector<block> flat_fmatch_encoding(mSize_fmatch *
                                     PAILLIER_CIPHER_SIZE_IN_BLOCK);
  coproto::sync_wait(sockets[0].recvResize(flat_fmatch_encoding));
  coproto::sync_wait(sockets[0].flush());

  auto fmatch_encoding =
      chunkFixedSizeBlocks(flat_fmatch_encoding, PAILLIER_CIPHER_SIZE_IN_BLOCK);

  RBOKVS rb_okvs_fmatch;
  rb_okvs_fmatch.init(mN_fmatch, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  vector<vector<BigNumber>> fmatch_bns(DIM);
  for (u64 i = 0; i < OTHER_PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      auto tmp = rb_okvs_fmatch.decode(fmatch_encoding,
                                       get_key_from_pt_dim(sum[i * DIM + j], j),
                                       PAILLIER_CIPHER_SIZE_IN_BLOCK);
      fmatch_bns[j].push_back(block_vector_to_bignumer(tmp));
    }
  }

  auto dim0 = ipcl::CipherText(palliar_pk, fmatch_bns[0]);
  for (u64 i = 1; i < DIM; i++) {
    auto tmp = ipcl::CipherText(palliar_pk, fmatch_bns[i]);
    dim0 = dim0 + tmp;
  }

  auto add_cipher_blks = bignumers_to_block_vector(dim0.getTexts());
  coproto::sync_wait(sockets[0].send(add_cipher_blks));
  coproto::sync_wait(sockets[0].flush());
}