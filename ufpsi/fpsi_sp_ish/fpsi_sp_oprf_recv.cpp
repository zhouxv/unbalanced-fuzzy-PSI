#include <cmath>
#include <ipcl/plaintext.hpp>
#include <ipcl/utils/context.hpp>
#include <spdlog/spdlog.h>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <vector>

#include "config.h"
#include "fpsi_sp_oprf_recv.h"
#include "rb_okvs/rb_okvs.h"
#include "rr22/Oprf.h"
#include "utils/util.h"

void PsiSpRecvISH::offline_hash() {
  // {x_dim||dim}
  oprf_keys.resize(PTS_NUM * DIM);
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      oprf_keys[i * DIM + j] = block(pts[i][j], j);
    }
  }
}

void PsiSpRecvISH::phase3_offline() {
  masks.reserve(PTS_NUM * DIM);
  vector<BigNumber> masks_bns(PTS_NUM * DIM);

  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      masks[i * DIM + j] = prng.get<u64>() / 2;
      masks_bns[i * DIM + j] =
          BigNumber(reinterpret_cast<Ipp32u *>(&masks[i * DIM + j]), 2);
    }
  }

  ipcl::PlainText mask_pts = ipcl::PlainText(masks_bns);
  masks_ciphers = palliar_pk.encrypt(mask_pts);
}

void PsiSpRecvISH::fuzzy_matching_offline() {

  vector<u32> zero_vec(2 * DELTA + 1, 0);
  ipcl::PlainText zero_plain = ipcl::PlainText(zero_vec);
  ipcl::CipherText zero_ciphers = palliar_pk.encrypt(zero_plain);

  auto zero_ciphers_blks = bignumers_to_blocks_vector(zero_ciphers.getTexts());

  RBOKVS rb_okvs;
  rb_okvs.init(PTS_NUM * DIM * (2 * DELTA + 1), OKVS_EPSILON, OKVS_LAMBDA,
               OKVS_SEED);

  fmatch_values.resize((PTS_NUM * DIM * (2 * DELTA + 1)));
  for (u64 i = 0; i < PTS_NUM * DIM; i++) {
    for (u64 j = 0; j < 2 * DELTA + 1; j++) {
      fmatch_values[i * (2 * DELTA + 1) + j] = zero_ciphers_blks[j];
    }
  }
}

void PsiSpRecvISH::online_hash() {

  /// PSV Recv Step 1

  vector<block> oprf_vals(PTS_NUM * DIM);

  volePSI::RsOprfReceiver oprfRecv;
  coproto::sync_wait(oprfRecv.receive(oprf_keys, oprf_vals, prng, sockets[0]));

  spdlog::debug("P2 Step 1 oprf finished");

  /// PSV Recv Step 3 and Step 4
  u64 mN = OTHER_PTS_NUM * (2 * DELTA + 1);
  u64 mSize;
  coproto::sync_wait(sockets[0].recv(mSize));
  coproto::sync_wait(sockets[0].flush());

  vector<vector<block>> encodings(DIM, vector<block>(mSize));

  for (u64 i = 0; i < DIM; i++) {
    coproto::sync_wait(sockets[0].recvResize(encodings[i]));
  }
  coproto::sync_wait(sockets[0].flush());

  RBOKVS rb_okvs;
  rb_okvs.init(mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  H2_sums.resize(PTS_NUM, ZeroBlock);

  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      auto tmp = rb_okvs.decode(encodings[j].data(), block(pts[i][j], j));
      H2_sums[i] = H2_sums[i] ^ tmp ^ oprf_vals[i * DIM + j];
    }
  }

  oprf_keys.clear();
  oprf_keys.shrink_to_fit();
}

void PsiSpRecvISH::offline() {
  offline_hash();
  phase3_offline();
  fuzzy_matching_offline();
}

void PsiSpRecvISH::online() {
  online_hash();

  u64 setup_mN;
  u64 setup_mSize;
  coproto::sync_wait(sockets[0].recv(setup_mN));
  coproto::sync_wait(sockets[0].recv(setup_mSize));
  coproto::sync_wait(sockets[0].flush());

  vector<vector<block>> setup_encoding;
  vector<block> setup_encoding_flat(setup_mSize *
                                    PAILLIER_CIPHER_SIZE_IN_BLOCK);
  coproto::sync_wait(sockets[0].recvResize(setup_encoding_flat));
  coproto::sync_wait(sockets[0].flush());

  setup_encoding =
      chunkFixedSizeBlocks(setup_encoding_flat, PAILLIER_CIPHER_SIZE_IN_BLOCK);

  RBOKVS decode_okvs;
  decode_okvs.init(setup_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  vector<BigNumber> decode_bns(PTS_NUM * DIM);
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      decode_bns[i * DIM + j] = block_vector_to_bignumer(decode_okvs.decode(
          setup_encoding, get_key_from_sum_dim(H2_sums[i], j),
          PAILLIER_CIPHER_SIZE_IN_BLOCK));
    }
  }

  auto sum_ciphers = ipcl::CipherText(palliar_pk, decode_bns) + masks_ciphers;

  auto sum_ciphers_blks = bignumers_to_block_vector(sum_ciphers.getTexts());
  coproto::sync_wait(sockets[0].send(sum_ciphers.getSize()));
  coproto::sync_wait(sockets[0].flush());

  coproto::sync_wait(sockets[0].send(sum_ciphers_blks));
  coproto::sync_wait(sockets[0].flush());

  vector<block> fmatch_keys;
  fmatch_keys.reserve(PTS_NUM * DIM * (2 * (DELTA + 1)));
  // Fmatch
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      auto tmp = pts[i][j] + masks[i * DIM + j];
      for (u64 i = tmp - DELTA; i <= tmp + DELTA; i++) {
        fmatch_keys.push_back(get_key_from_pt_dim(i, j));
      }
    }
  }

  std::unordered_set<block> fmatch_keys_set(fmatch_keys.begin(),
                                            fmatch_keys.end());
  std::vector<block> fmatch_keys_re(fmatch_keys_set.begin(),
                                    fmatch_keys_set.end());

  padding_keys(fmatch_keys_re, fmatch_values.size());

  RBOKVS fmatch_okvr;
  fmatch_okvr.init(fmatch_keys_re.size(), OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  vector<vector<block>> fmatch_encoding(
      fmatch_okvr.mSize, vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));
  fmatch_okvr.encode(fmatch_keys_re, fmatch_values,
                     PAILLIER_CIPHER_SIZE_IN_BLOCK, fmatch_encoding);

  auto flat_fmatch_encoding = flattenBlocks(fmatch_encoding);

  coproto::sync_wait(sockets[0].send(fmatch_okvr.mN));
  coproto::sync_wait(sockets[0].send(fmatch_okvr.mSize));
  coproto::sync_wait(sockets[0].flush());
  coproto::sync_wait(sockets[0].send(flat_fmatch_encoding));
  coproto::sync_wait(sockets[0].flush());

  vector<block> add_cipher_blks;
  coproto::sync_wait(sockets[0].recvResize(add_cipher_blks));
  coproto::sync_wait(sockets[0].flush());

  auto add_cipher_bns = block_vector_to_bignumers(add_cipher_blks, PTS_NUM);

  auto fmatch_res_pt =
      palliar_sk.decrypt(ipcl::CipherText(palliar_pk, add_cipher_bns));

  vector<u64> fmatch_res(PTS_NUM);
  for (u64 i = 0; i < PTS_NUM; i++) {
    auto tmp = fmatch_res_pt.getElementVec(i);
    fmatch_res[i] = tmp[0];
  }

  for (auto tmp : fmatch_res) {
    if (tmp == 0) {
      psi_ca_result = psi_ca_result + 1;
    }
  }
}