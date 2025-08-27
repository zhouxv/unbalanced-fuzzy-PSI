#include <cmath>
#include <ipcl/plaintext.hpp>
#include <ipcl/utils/context.hpp>
#include <spdlog/spdlog.h>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>

#include "rb_okvs/rb_okvs.h"
#include "rr22/Oprf.h"
#include "shash_oprf_p2.h"

void ShashOprfP2::offline_hash() {
  // {x_dim||dim}
  oprf_keys.resize(PTS_NUM * DIM);
  for (u64 i = 0; i < PTS_NUM; i++) {
    for (u64 j = 0; j < DIM; j++) {
      oprf_keys[i * DIM + j] = block(pts[i][j], j);
    }
  }
}

void ShashOprfP2::online_hash() {

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

  spdlog::debug("P2 Step 3 finish recv");

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
