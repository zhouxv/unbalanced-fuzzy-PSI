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
#include "rb_okvs/rb_okvs.h"
#include "shash_ahe_p2.h"
#include "utils/util.h"

void ShashAheP2::offline() {
  masks.resize(PTS_NUM);
  vector<BigNumber> masks_bns(PTS_NUM);

  for (u64 i = 0; i < PTS_NUM; i++) {
    masks[i] = prng.get<u64>() >> DIM;
    masks_bns[i] = BigNumber(reinterpret_cast<Ipp32u *>(&masks[i]), 2);
  }

  ipcl::PlainText masks_pts = ipcl::PlainText(masks_bns);
  masks_cipher = palliar_pk.encrypt(masks_pts);
}

void ShashAheP2::online(vector<vector<vector<block>>> &shash_encodings) {
  u64 shash_mN;
  u64 shash_mSize;
  coproto::sync_wait(sockets[0].recv(shash_mN));
  coproto::sync_wait(sockets[0].recv(shash_mSize));
  coproto::sync_wait(sockets[0].flush());

  RBOKVS rb_okvs;
  rb_okvs.init(shash_mN, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);

  vector<vector<BigNumber>> sum_bns(DIM, vector<BigNumber>(PTS_NUM));
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      sum_bns[j][i] = block_vector_to_bignumer(
          rb_okvs.decode(shash_encodings[j], get_key_from_pt_dim(pts[i][j], j),
                         PAILLIER_CIPHER_SIZE_IN_BLOCK));
    }
  }

  shash_encodings.clear();
  shash_encodings.shrink_to_fit();

  vector<ipcl::CipherText> sum_ciphers(DIM);
  for (u64 i = 0; i < DIM; i++) {
    sum_ciphers[i] = ipcl::CipherText(palliar_pk, sum_bns[i]);
  }
  for (u64 i = 1; i < DIM; i++) {
    sum_ciphers[0] = sum_ciphers[0] + sum_ciphers[i];
  }

  sum_ciphers[0] = sum_ciphers[0] + masks_cipher;

  auto sum_blks = bignumers_to_block_vector(sum_ciphers[0].getTexts());

  coproto::sync_wait(sockets[0].send(sum_blks));
  coproto::sync_wait(sockets[0].flush());

  vector<u64> res(PTS_NUM);
  coproto::sync_wait(sockets[0].recvResize(res));
  coproto::sync_wait(sockets[0].flush());

  // for (u64 i = 0; i < 5; i++) {
  //   std::cout << "i " << i << " " << res[i] - masks[i] << endl;
  // }
}