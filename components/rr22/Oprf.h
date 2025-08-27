#pragma once

#include "cryptoTools/Common/Defines.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"

#include "Paxos.h"
#include <span>

namespace volePSI {

using PRNG = oc::PRNG;
using Socket = coproto::Socket;
using Proto = coproto::task<void>;

class RsOprfSender : public oc::TimerAdapter {
public:
  oc::SilentVoleSender<block, block, oc::CoeffCtxGF128> mVoleSender;
  std::span<block> mB;
  block mD;
  Baxos mPaxos;
  bool mMalicious = false;
  block mW;
  u64 mBinSize = 1 << 14;
  u64 mSsp = 40;
  bool mDebug = false;

  void setMultType(oc::MultType type) { mVoleSender.mLpnMultType = type; };

  Proto send(u64 n, PRNG &prng, Socket &chl, u64 mNumThreads = 0,
             bool reducedRounds = false);

  block eval(block v);

  void eval(std::span<const block> val, std::span<block> output,
            u64 mNumThreads = 0);

  Proto genVole(PRNG &prng, Socket &chl, bool reducedRounds);
};

class RsOprfReceiver : public oc::TimerAdapter {

public:
  bool mMalicious = false;
  oc::SilentVoleReceiver<block, block, oc::CoeffCtxGF128> mVoleRecver;
  u64 mBinSize = 1 << 14;
  u64 mSsp = 40;
  bool mDebug = false;

  void setMultType(oc::MultType type) { mVoleRecver.mLpnMultType = type; };

  Proto receive(std::span<const block> values, std::span<block> outputs,
                PRNG &prng, Socket &chl, u64 mNumThreads = 0,
                bool reducedRounds = false);

  Proto genVole(u64 n, PRNG &prng, Socket &chl, bool reducedRounds);
};
} // namespace volePSI