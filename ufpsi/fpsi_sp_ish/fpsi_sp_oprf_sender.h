#pragma once
#include <coproto/Socket/Socket.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/block.h>
#include <vector>

#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/pri_key.hpp>
#include <ipcl/pub_key.hpp>

#include "config.h"
#include "fpsi_base.h"
#include "rb_okvs/rb_okvs.h"
#include "utils/util.h"

class PsiSpSenderISH : public FPSIBase {
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
  vector<vector<u64>> shash_keys;
  vector<vector<block>> shash_keys_blocks;
  vector<vector<block>> shash_values;
  PRNG prng;
  vector<block> H1_sums;

  //
  vector<vector<block>> setup_encoding;

  void clear() {
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
    }
    commus.clear();
    fpsi_timer.clear();
  }

  PsiSpSenderISH(u64 dim, u64 delta, u64 pt_num, u64 other_pt_num,
                 u64 thread_num, ipcl::PublicKey &pk, ipcl::PrivateKey &sk,
                 vector<pt> &pts, vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), OTHER_PTS_NUM(other_pt_num),
        THREAD_NUM(thread_num), palliar_pk(pk), palliar_sk(sk), pts(pts),
        FPSIBase(sockets) {
    prng.SetSeed(oc::sysRandomSeed());
  };

  void offline_hash();
  void setup();

  void online_hash();
  void offline();
  void online();
};