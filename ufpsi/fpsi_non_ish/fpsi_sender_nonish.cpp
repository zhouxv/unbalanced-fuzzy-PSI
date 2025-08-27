#include "fpsi_sender_nonish.h"
#include "config.h"
#include "rb_okvs/rb_okvs.h"
#include "utils/util.h"

#include <cmath>
#include <ipcl/plaintext.hpp>
#include <ipcl/utils/context.hpp>
#include <libOTe/Base/BaseOT.h>
#include <libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h>
#include <spdlog/spdlog.h>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <vector>

void PsiSenderNonISH::non_isp_offline() {
  H2_sums.reserve(PTS_NUM);
  auto side_len = (SIGMA) ? 4 * DELTA : DELTA;
  for (auto pt : pts) {
    H2_sums.push_back(get_key_from_point(cell(pt, DIM, side_len)));
  }
}

void PsiSenderNonISH::offline() { non_isp_offline(); }

void PsiSenderNonISH::online() {
  u64 setup_mN;
  u64 setup_mSize;
  coproto::sync_wait(sockets[0].recv(setup_mN));
  coproto::sync_wait(sockets[0].recv(setup_mSize));
  coproto::sync_wait(sockets[0].flush());

  auto flat_encoding = setup_mSize * PAILLIER_CIPHER_SIZE_IN_BLOCK;
  auto deal = flat_encoding / COM_CHUNK_SIZE;
  auto remainder = flat_encoding % COM_CHUNK_SIZE;

  vector<block> setup_encoding_flat;
  setup_encoding_flat.reserve(setup_mSize * PAILLIER_CIPHER_SIZE_IN_BLOCK);

  for (u64 i = 0; i < deal; i++) {
    vector<block> tmp_block(COM_CHUNK_SIZE);
    coproto::sync_wait(sockets[0].recvResize(tmp_block));
    setup_encoding_flat.insert(setup_encoding_flat.end(), tmp_block.begin(),
                               tmp_block.end());
  }
  vector<block> last_blocks(remainder);
  coproto::sync_wait(sockets[0].recvResize(last_blocks));
  setup_encoding_flat.insert(setup_encoding_flat.end(), last_blocks.begin(),
                             last_blocks.end());

  vector<vector<block>> setup_encoding =
      chunkFixedSizeBlocks(setup_encoding_flat, PAILLIER_CIPHER_SIZE_IN_BLOCK);

  RBOKVS decode_okvs;
  decode_okvs.init(setup_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  vector<vector<BigNumber>> decode_bns(DIM);

  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      auto tmp_key = get_key_from_sum_dim_x(H2_sums[i], j, pts[i][j]);
      auto tmp_res = decode_okvs.decode(setup_encoding, tmp_key,
                                        PAILLIER_CIPHER_SIZE_IN_BLOCK);
      decode_bns[j].push_back(block_vector_to_bignumer(tmp_res));
    }
  }

  auto dim0 = ipcl::CipherText(palliar_pk, decode_bns[0]);
  for (u64 i = 1; i < DIM; i++) {
    auto tmp = ipcl::CipherText(palliar_pk, decode_bns[i]);
    dim0 = dim0 + tmp;
  }

  auto add_cipher_blks = bignumers_to_block_vector(dim0.getTexts());
  coproto::sync_wait(sockets[0].send(dim0.getSize()));
  coproto::sync_wait(sockets[0].flush());

  coproto::sync_wait(sockets[0].send(add_cipher_blks));
  coproto::sync_wait(sockets[0].flush());

  const u64 numOTs = PTS_NUM * DIM;
  // baseOT recv
  osuCrypto::DefaultBaseOT baseOTs;
  vector<block> baseRecv(128);
  BitVector baseChoice(128);
  baseChoice.randomize(prng);

  auto p = baseOTs.receive(baseChoice, baseRecv, prng, sockets[0]);
  auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
  std::get<0>(r).result();

  // iknp sender
  IknpOtExtSender sender;
  sender.setBaseOts(baseRecv, baseChoice);
  vector<array<block, 2>> sendMsg(numOTs);
  vector<block> half_sendMsg_0(numOTs);
  vector<block> half_sendMsg_1(numOTs);

  auto proto = sender.send(sendMsg, prng, sockets[0]);
  auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
  std::get<0>(result).result();

  // random OT -> OT
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      half_sendMsg_0[i * DIM + j] = prng.get<block>() ^ sendMsg[i][0];
      half_sendMsg_1[i * DIM + j] = block(pts[i][j]) ^ sendMsg[i][1];
    }
  }
  coproto::sync_wait(sockets[0].send(half_sendMsg_0));
  coproto::sync_wait(sockets[0].send(half_sendMsg_1));
}
