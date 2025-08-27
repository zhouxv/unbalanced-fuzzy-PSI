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

class ShashOprfP2 : public FPSIBase {
public:
  const u64 DIM;
  const u64 DELTA;
  const u64 PTS_NUM;
  const u64 OTHER_PTS_NUM;
  const u64 THREAD_NUM;

  vector<pt> &pts;

  // shash datas
  PRNG prng;
  vector<block> oprf_keys;
  vector<block> H2_sums;

  void clear() {
    for (auto socket : sockets) {
      socket.mImpl->mBytesSent = 0;
    }
    commus.clear();
    fpsi_timer.clear();
  }

  ShashOprfP2(u64 dim, u64 delta, u64 pt_num, u64 other_pt_num, u64 thread_num,
              vector<pt> &pts, vector<coproto::Socket> &sockets)
      : DIM(dim), DELTA(delta), PTS_NUM(pt_num), OTHER_PTS_NUM(other_pt_num),
        THREAD_NUM(thread_num), pts(pts), FPSIBase(sockets) {

    prng.SetSeed(oc::sysRandomSeed());
  };

  void offline_hash();

  void online_hash();
};
