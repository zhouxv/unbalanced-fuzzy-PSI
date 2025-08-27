#pragma once
#include <coproto/Socket/Socket.h>
#include <vector>

#include <cryptoTools/Common/block.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/pri_key.hpp>

#include "config.h"
#include "fpsi_base.h"
#include "utils/util.h"

class PsiSpRecvNonISH : public FPSIBase {
public:
  const u64 DIM;
  const u64 DELTA;
  const u64 PTS_NUM;
  const u64 OTHER_PTS_NUM;
  const u64 THREAD_NUM;
  const bool SIGMA;

  u64 SIDE_LEN;
  u64 BLK_CELLS;

  vector<pt> &pts;

  const ipcl::PublicKey palliar_pk;
  const ipcl::PrivateKey palliar_sk;

  // shash datas
  PRNG prng;
  vector<block> oprf_keys;
  vector<block> H2_sums;

  //
  vector<u64> masks;
  ipcl::CipherText masks_ciphers;

  //
  vector<vector<block>> fmatch_values;

  u64 psi_ca_result = 0;

  void clear() {
    psi_ca_result = 0;
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
    }
    commus.clear();
    fpsi_timer.clear();
  }

  PsiSpRecvNonISH(u64 dim, u64 delta, u64 pt_num, u64 other_pt_num,
                  u64 thread_num, ipcl::PublicKey &pk, ipcl::PrivateKey &sk,
                  vector<pt> &pts, bool sigma, vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), OTHER_PTS_NUM(other_pt_num),
        THREAD_NUM(thread_num), palliar_pk(pk), palliar_sk(sk), pts(pts),
        SIGMA(sigma), FPSIBase(sockets) {
    prng.SetSeed(oc::sysRandomSeed());

    SIDE_LEN = (sigma) ? 4 * delta : delta;
    BLK_CELLS = (sigma) ? (1 << dim) : (std::pow(3, dim));
  };

  void non_isp_offline();
  void phase3_offline();
  void fuzzy_matching_offline();
  void offline();

  void online();
};
