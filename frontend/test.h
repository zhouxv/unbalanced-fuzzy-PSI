#pragma once

#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>
#include <macoro/task.h>

void test_oprf(const oc::CLP &cmd);

void test_ecc_elgamal(const oc::CLP &cmd);

void test_palliar(const oc::CLP &cmd);

void test_flat_and_recovery(const oc::CLP &cmd);

void test_paxos_param(const oc::CLP &cmd);

void test_intersection(const oc::CLP &cmd);

void test_okvs(const oc::CLP &cmd);

void test_paxos(const oc::CLP &cmd);

inline auto eval(macoro::task<> &t0, macoro::task<> &t1) {
  auto r =
      macoro::sync_wait(macoro::when_all_ready(std::move(t0), std::move(t1)));
  std::get<0>(r).result();
  std::get<1>(r).result();
}
