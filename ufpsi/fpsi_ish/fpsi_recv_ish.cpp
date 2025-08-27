#include "fpsi_recv_ish.h"
#include "config.h"
#include "rb_okvs/rb_okvs.h"
#include "rr22/Oprf.h"
#include "rr22/Paxos.h"
#include "utils/util.h"

#include <algorithm>
#include <ipcl/utils/context.hpp>
#include <iterator>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <vector>

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <spdlog/spdlog.h>

void PsiRecvISH::offline_hash() {

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

void PsiRecvISH::online_hash() {

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
  auto okvr_mSize = rb_okvs_vec[0].mSize;
  vector<vector<block>> encodings(DIM, vector<block>(okvr_mSize, ZeroBlock));

  for (u64 i = 0; i < DIM; i++) {
    rb_okvs_vec[i].encode(okvr_keys[i].data(), okvr_values[i].data(),
                          encodings[i].data());
  }

  coproto::sync_wait(sockets[0].send(okvr_mSize));
  coproto::sync_wait(sockets[0].flush());

  auto tmp_com = sockets[0].mImpl->mBytesSent;
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

void PsiRecvISH::setup() {
  u64 okvr_size = PTS_NUM * DIM * (2 * DELTA + 1);
  // note: random gen
  // ipcl::initializeContext("QAT");
  // ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  // vector<u32> zero_vec(2 * DELTA + 1, 0);
  // ipcl::PlainText zero_plain = ipcl::PlainText(zero_vec);
  // ipcl::CipherText zero_ciphers = palliar_pk.encrypt(zero_plain);
  // auto zero_ciphers_blks =
  // bignumers_to_blocks_vector(zero_ciphers.getTexts());

  // ipcl::terminateContext();

  // vector<block> keys(okvr_size);
  // vector<vector<block>> values(okvr_size);

  // u64 tmplen2 = 2 * DELTA + 1;
  // u64 tmplen1 = DIM * (2 * DELTA + 1);

  // for (u64 i = 0; i < PTS_NUM; i++) {
  //   for (u64 j = 0; j < DIM; j++) {
  //     auto start = pts[i][j] - DELTA;
  //     auto end = pts[i][j] + DELTA;
  //     u64 count = 0;
  //     for (u64 ii = start; ii <= end; ii++) {
  //       auto tmp = i * tmplen1 + j * tmplen2 + count;
  //       keys[tmp] = get_key_from_sum_dim_x(H1_sums[i], j, ii);
  //       values[tmp] = zero_ciphers_blks[count];
  //       count++;
  //     }
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

void PsiRecvISH::offline() {
  offline_hash();
  setup();
}

void PsiRecvISH::online() {
  online_hash();

  u64 setup_mN = PTS_NUM * DIM * (2 * DELTA + 1);
  coproto::sync_wait(sockets[0].send(setup_mN));
  coproto::sync_wait(sockets[0].send(setup_encoding.size()));
  coproto::sync_wait(sockets[0].flush());

  auto flat_encode_blocks = flattenBlocks(setup_encoding);

  auto tmp_com = sockets[0].bytesSent();

  auto flat_size = flat_encode_blocks.size();
  auto deal = flat_size / COM_CHUNK_SIZE;
  auto remainder = flat_size % COM_CHUNK_SIZE;

  for (u64 i = 0; i < deal; i++) {
    std::span<block> view(flat_encode_blocks.data() + i * COM_CHUNK_SIZE,
                          COM_CHUNK_SIZE);
    coproto::sync_wait(sockets[0].send(view));
  }

  std::span<block> view(flat_encode_blocks.data() + deal * COM_CHUNK_SIZE,
                        remainder);
  coproto::sync_wait(sockets[0].send(view));
  coproto::sync_wait(sockets[0].flush());

  u64 sum_size;
  coproto::sync_wait(sockets[0].recv(sum_size));
  coproto::sync_wait(sockets[0].flush());
  vector<block> sum_blks(sum_size * PAILLIER_CIPHER_SIZE_IN_BLOCK);
  coproto::sync_wait(sockets[0].recvResize(sum_blks));
  coproto::sync_wait(sockets[0].flush());

  setup_encoding.clear();
  setup_encoding.shrink_to_fit();

  auto sum_bns = block_vector_to_bignumers(sum_blks, sum_size);
  auto sum_dec = palliar_sk.decrypt(ipcl::CipherText(palliar_pk, sum_bns));

  vector<u64> sum(sum_size);
  for (u64 i = 0; i < sum_size; i++) {
    auto tmp = sum_dec.getElementVec(i);
    sum[i] = tmp[0];
  }

  for (auto tmp : sum) {
    if (tmp == 0) {
      psi_ca_result = psi_ca_result + 1;
    }
  }

  u64 numOTs = OTHER_PTS_NUM * DIM;
  // baseOT send
  osuCrypto::DefaultBaseOT baseOTs;
  vector<array<block, 2>> baseSend(128);
  prng.get((u8 *)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
  auto p = baseOTs.send(baseSend, prng, sockets[0]);
  auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
  std::get<0>(r).result();

  // iknp recv
  IknpOtExtReceiver recv;
  recv.setBaseOts(baseSend);

  vector<block> recvMsg;
  recvMsg.resize(numOTs);

  BitVector s0(numOTs);
  for (u64 i = 0; i < OTHER_PTS_NUM; i++) {
    if (sum[i] == 0) {
      for (u64 j = 0; j < DIM; j++) {
        s0[i * DIM + j] = 1;
      }
    }
  }

  auto proto = recv.receive(s0, recvMsg, prng, sockets[0]);
  auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
  std::get<0>(result).result();

  vector<block> mask_msg_0(numOTs);
  vector<block> mask_msg_1(numOTs);
  coproto::sync_wait(sockets[0].recv(mask_msg_0));
  coproto::sync_wait(sockets[0].recv(mask_msg_1));

  for (u64 i = 0; i < numOTs; i++) {
    recvMsg[i] =
        (s0[i]) ? (recvMsg[i] ^ mask_msg_1[i]) : (recvMsg[i] ^ mask_msg_0[i]);
  }

  // for (u64 i = 0; i < 5; i++) {
  //   for (u64 j = 0; j < DIM; j++) {
  //     cout << recvMsg[i * DIM + j].get<u64>()[0] << " ";
  //   }
  //   cout << endl;
  // }
}