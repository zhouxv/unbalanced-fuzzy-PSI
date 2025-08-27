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
#include "fpsi_sp_sender_nonish.h"
#include "rb_okvs/rb_okvs.h"
#include "rr22/Oprf.h"
#include "utils/util.h"

void PsiSpSenderNonISH::non_isp_offline() {
  H1_sums.resize(PTS_NUM);
  for (u64 i = 0; i < H1_sums.size(); i++) {
    auto cells = intersection(pts[i], DIM, DELTA, SIGMA);
    for (auto cell : cells) {
      H1_sums[i].push_back(get_key_from_point(cell));
    }
  }
  spdlog::debug("sender nonish offline 完成");
}

void PsiSpSenderNonISH::setup() {
  u64 okvr_size = PTS_NUM * DIM * BLK_CELLS;
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
  // auto pt_ciphers_blks = bignumers_to_blocks_vector(pt_ciphers.getTexts());
  // ipcl::terminateContext();

  // vector<block> keys;
  // vector<vector<block>> values;
  // keys.reserve(okvr_size);
  // values.reserve(okvr_size);

  // for (u64 i = 0; i < PTS_NUM; i++) {
  //   for (u64 j = 0; j < DIM; j++) {
  //     for (u64 index = 0; index < BLK_CELLS; index++) {
  //       keys.push_back(get_key_from_sum_dim(H1_sums[i][index], j));
  //       values.push_back(pt_ciphers_blks[i * DIM + j]);
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

  spdlog::debug("Sender setup encoding 模拟完成");

  H1_sums.clear();
  H1_sums.shrink_to_fit();
};

void PsiSpSenderNonISH::offline() {
  non_isp_offline();
  setup();
}

void PsiSpSenderNonISH::online() {

  auto setup_mN = DIM * PTS_NUM * BLK_CELLS;
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