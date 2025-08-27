#include "fpsi_recv_nonish.h"
#include "config.h"
#include "rb_okvs/rb_okvs.h"
#include "rr22/Paxos.h"
#include "utils/util.h"

#include <ipcl/utils/context.hpp>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h>
#include <vector>

#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/plaintext.hpp>
#include <spdlog/spdlog.h>

void PsiRecvNonISH::non_isp_offline() {
  H1_sums.resize(PTS_NUM);
  for (u64 i = 0; i < H1_sums.size(); i++) {
    auto cells = intersection(pts[i], DIM, DELTA, SIGMA);
    for (auto cell : cells) {
      H1_sums[i].push_back(get_key_from_point(cell));
    }
  }
}

void PsiRecvNonISH::setup() {
  u64 okvr_size = PTS_NUM * DIM * (2 * DELTA + 1) * BLK_CELLS;

  // note: random gen
  // ipcl::initializeContext("QAT");
  // ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  // vector<u32> zero_vec(2 * DELTA + 1, 0);
  // ipcl::PlainText zero_plain = ipcl::PlainText(zero_vec);
  // ipcl::CipherText zero_ciphers = palliar_pk.encrypt(zero_plain);
  // auto zero_ciphers_blks =
  // bignumers_to_blocks_vector(zero_ciphers.getTexts());

  // ipcl::terminateContext();

  // vector<block> keys;
  // vector<vector<block>> values;

  // keys.reserve(okvr_size);
  // values.reserve(okvr_size);

  // for (u64 i = 0; i < PTS_NUM; i++) {
  //   for (u64 j = 0; j < DIM; j++) {
  //     auto start = pts[i][j] - DELTA;
  //     auto end = pts[i][j] + DELTA;
  //     u64 count = 0;
  //     for (u64 ii = start; ii <= end; ii++) {
  //       for (auto tmpsum : H1_sums[i]) {
  //         keys.push_back(get_key_from_sum_dim_x(tmpsum, j, ii));
  //         values.push_back(zero_ciphers_blks[count]);
  //       }
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

  for (auto tmp : H1_sums) {
    tmp.clear();
    tmp.shrink_to_fit();
  }
};

void PsiRecvNonISH::offline() {
  non_isp_offline();
  setup();
}

void PsiRecvNonISH::online() {

  auto setup_mN = DIM * PTS_NUM * BLK_CELLS * (2 * DELTA + 1);
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

  setup_encoding.clear();
  setup_encoding.shrink_to_fit();

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