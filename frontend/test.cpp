#include "test.h"

#include <cryptoTools/Common/block.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <ipcl/bignum.h>
#include <ipcl/ciphertext.hpp>
#include <ipcl/ipcl.hpp>
#include <ipcl/plaintext.hpp>
#include <openssl/types.h>
#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <coproto/Socket/AsioSocket.h>
#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <vector>

#include "config.h"
#include "rb_okvs/rb_okvs.h"
#include "rr22/Oprf.h"
#include "rr22/Paxos.h"
#include "utils/util.h"

using namespace osuCrypto;

void test_oprf(const oc::CLP &cmd) {
  volePSI::RsOprfSender sender;
  volePSI::RsOprfReceiver recver;

  auto sockets = coproto::LocalAsyncSocket::makePair();
  u64 n = 4000;
  PRNG prng0(block(0, 0));
  PRNG prng1(block(0, 1));

  std::vector<block> vals(n), recvOut(n);

  prng0.get(vals.data(), n);

  auto p0 = sender.send(n, prng0, sockets[0]);
  auto p1 = recver.receive(vals, recvOut, prng1, sockets[1]);

  eval(p0, p1);

  std::vector<block> vv(n);
  sender.eval(vals, vv);

  u64 count = 0;
  for (u64 i = 0; i < n; ++i) {
    auto v = sender.eval(vals[i]);
    if (i < 10) {
      std::cout << i << " " << recvOut[i] << " " << v << " " << vv[i]
                << std::endl;
    }
  };
}

void test_ecc_elgamal(const oc::CLP &cmd) {

  PRNG prng(oc::sysRandomSeed());
  REllipticCurve curve; //(CURVE_25519)
  const auto &g = curve.getGenerator();

  REccNumber sk_ecc(curve);
  sk_ecc.randomize(prng);
  REccPoint pk_ecc = g * sk_ecc;

  std::vector<u8> sk_ecc_vec(g.sizeBytes() - 1);
  sk_ecc.toBytes(sk_ecc_vec.data());
  std::vector<u8> pk_ecc_vec(g.sizeBytes());
  pk_ecc.toBytes(pk_ecc_vec.data());
}

void test_palliar(const oc::CLP &cmd) {
  PRNG prng(oc::sysRandomSeed());

  ipcl::initializeContext("QAT");
  ipcl::KeyPair paillier_key = ipcl::generateKeypair(2048, true);
  ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);

  auto num_count = 10;
  vector<u32> numbers(num_count);

  for (int i = 0; i < num_count; i++) {
    numbers[i] = prng.get<u32>();
  }

  ipcl::PlainText pt = ipcl::PlainText(numbers);
  ipcl::CipherText ct = paillier_key.pub_key.encrypt(pt);

  auto bns = ct.getChunk(0, num_count);

  auto blks = bignumers_to_block_vector(bns);
  auto bns_2 =
      block_vector_to_bignumers(blks, num_count, paillier_key.pub_key.getNSQ());

  auto dec_pt = paillier_key.priv_key.decrypt(
      ipcl::CipherText(paillier_key.pub_key, bns_2));

  bool verify = true;
  for (int i = 0; i < num_count; i++) {
    std::vector<uint32_t> v = dec_pt.getElementVec(i);
    if (v[0] != numbers[i]) {
      verify = false;
      break;
    }
  }
  std::cout << "Test pt == dec(enc(pt)) -- " << (verify ? "pass" : "fail")
            << std::endl;

  ipcl::terminateContext();
  std::cout << "Complete!" << std::endl << std::endl;
}

void test_flat_and_recovery(const oc::CLP &cmd) {
  vector<vector<block>> blks(3);
  PRNG prng(oc::sysRandomSeed());
  for (u64 i = 0; i < 3; i++) {
    for (u64 j = 0; j < 3; j++) {
      auto tmp = prng.get<block>();
      cout << tmp << "  ";
      blks[i].push_back(tmp);
    }
    cout << endl;
  }
  cout << endl;

  auto flat = flattenBlocks(blks);
  for (auto a : flat) {
    cout << a << "  ";
  }
  cout << endl;
  cout << flat.size() << endl;

  auto b = chunkFixedSizeBlocks(flat, 3);
  cout << b.size() << " " << b[0].size() << endl;
  for (u64 i = 0; i < b.size(); i++) {
    for (auto tmp : b[i]) {
      cout << tmp << "  ";
    }
    cout << endl;
  }
  cout << endl;
}

void test_paxos_param(const oc::CLP &cmd) {
  const u64 n = cmd.getOr("n", 10);
  const u64 ssp = cmd.getOr("ssp", 40);
  const u64 weight = cmd.getOr("w", 3);
  volePSI::PaxosParam a(1 << n, weight, ssp);
  spdlog::info("{} {}", a.mDenseSize, a.mSparseSize);
}

void test_intersection(const oc::CLP &cmd) {
  const u64 dim = cmd.getOr<u64>("d", 2);
  const u64 delta = cmd.getOr<u64>("delta", 2);
  const bool sigma = cmd.isSet("sigma");

  pt p(dim, delta);

  auto tmp = intersection(p, dim, delta, sigma);
  for (auto t : tmp) {
    for (auto a : t) {
      cout << a << " ";
    }
    cout << endl;
  }
}

void test_okvs(const oc::CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 10);
  const u64 PTS_NUM = 1ull << cmd.getOr("r", 18);
  const u64 num_s = 1ull << cmd.getOr("s", 5);

  // ipcl::initializeContext("QAT");
  // ipcl::setHybridMode(ipcl::HybridMode::OPTIMAL);
  // ipcl::KeyPair psi_key = ipcl::generateKeypair(2048, true);
  // vector<u32> zero_vec(2 * DELTA + 1, 0);
  // ipcl::PlainText zero_plain = ipcl::PlainText(zero_vec);
  // ipcl::CipherText zero_ciphers = psi_key.pub_key.encrypt(zero_plain);
  // auto zero_ciphers_blks =
  // bignumers_to_blocks_vector(zero_ciphers.getTexts());
  // ipcl::terminateContext();

  auto size = PTS_NUM * DIM * (2 * DELTA + 1);
  // vector<block> keys;
  // vector<vector<block>> values;
  PRNG prng(oc::sysRandomSeed());

  // for (u64 i = 0; i < PTS_NUM; i++) {
  //   for (u64 j = 0; j < DIM; j++) {
  //     for (u64 ii = 0; ii < 2 * DELTA + 1; ii++) {
  //       keys.push_back(prng.get<block>());
  //       values.push_back(zero_ciphers_blks[ii]);
  //     }
  //   }
  // }

  RBOKVS okvs;
  okvs.init(size, OKVS_EPSILON, OKVS_LAMBDA, OKVS_SEED);
  vector<vector<block>> encoding(okvs.mSize,
                                 vector<block>(PAILLIER_CIPHER_SIZE_IN_BLOCK));
  for (auto tmp : encoding) {
    prng.get<block>(tmp.data(), PAILLIER_CIPHER_SIZE_IN_BLOCK);
  }
  // okvs.encode(keys, values, PAILLIER_CIPHER_SIZE_IN_BLOCK, encoding);

  for (u64 i = 0; i < num_s; i++) {
    okvs.decode(encoding, prng.get<block>(), PAILLIER_CIPHER_SIZE_IN_BLOCK);
  }
}

void test_paxos(const oc::CLP &cmd) {

  u64 n = 1ull << cmd.getOr("n", 15);
  u64 w = cmd.getOr("w", 3);
  u64 s = cmd.getOr("s", 0);
  u64 t = cmd.getOr("t", 1);

  for (auto dt : {volePSI::PaxosParam::Binary, volePSI::PaxosParam::GF128}) {
    for (u64 tt = 0; tt < t; ++tt) {
      volePSI::Paxos<u16> paxos;
      volePSI::Paxos<u32> px2;
      paxos.init(n, w, 40, dt, ZeroBlock);
      px2.init(n, w, 40, dt, ZeroBlock);

      std::vector<block> items(n), values(n), values2(n), p(paxos.size());
      PRNG prng(block(tt, s));
      prng.get(items.data(), items.size());
      prng.get(values.data(), values.size());

      paxos.setInput(items);
      px2.setInput(items);

      for (u64 i = 0; i < paxos.mRows.rows(); ++i) {
        for (u64 j = 0; j < w; ++j) {
          auto v0 = paxos.mRows(i, j);
          auto v1 = px2.mRows(i, j);
          if (v0 != v1) {
            throw RTE_LOC;
          }
        }
      }

      paxos.encode<block>(values, p);
      paxos.decode<block>(items, values2, p);

      if (values2 != values) {
        throw RTE_LOC;
      }
    }
  }
}