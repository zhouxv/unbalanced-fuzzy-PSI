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

class PsiSenderISH : public FPSIBase {
public:
  const u64 DIM;
  const u64 DELTA;
  const u64 PTS_NUM;
  const u64 OTHER_PTS_NUM;
  const u64 THREAD_NUM;

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

  void clear() {
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
    }
    commus.clear();
    fpsi_timer.clear();
  }

  PsiSenderISH(u64 dim, u64 delta, u64 pt_num, u64 other_pt_num, u64 thread_num,
               ipcl::PublicKey &pk, ipcl::PrivateKey &sk, vector<pt> &pts,
               vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), OTHER_PTS_NUM(other_pt_num),
        THREAD_NUM(thread_num), palliar_pk(pk), palliar_sk(sk), pts(pts),
        FPSIBase(sockets) {

    prng.SetSeed(oc::sysRandomSeed());
  };

  void offline_hash();
  void offline();

  void online_hash();
  void online();
};
