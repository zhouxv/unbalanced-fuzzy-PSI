#include "fpsi_protocol.h"

#include <coproto/Socket/AsioSocket.h>
#include <coproto/Socket/LocalAsyncSock.h>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/RCurve.h>
#include <spdlog/spdlog.h>

#include "config.h"
#include "fpsi_ish/fpsi_recv_ish.h"
#include "fpsi_ish/fpsi_sender_ish.h"
#include "fpsi_non_ish/fpsi_recv_nonish.h"
#include "fpsi_non_ish/fpsi_sender_nonish.h"
#include "fpsi_sp_ish/fpsi_sp_oprf_recv.h"
#include "fpsi_sp_ish/fpsi_sp_oprf_sender.h"
#include "fpsi_sp_non_ish/fpsi_sp_recv_nonish.h"
#include "fpsi_sp_non_ish/fpsi_sp_sender_nonish.h"
#include "shash_ahe/shash_ahe_p1.h"
#include "shash_ahe/shash_ahe_p2.h"
#include "shash_oprf/shash_oprf_p1.h"
#include "shash_oprf/shash_oprf_p2.h"
#include "utils/util.h"

void run_psi_sp_ishash(const oc::CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 10);
  const u64 THREAD_NUM = 1;
  const u64 num_s = 1ull << cmd.getOr("s", 18);
  const u64 num_s_log = cmd.getOr("s", 18);
  const u64 num_r = 1ull << cmd.getOr("r", 5);
  const u64 num_r_log = cmd.getOr("r", 5);
  const u64 intersection_size = cmd.getOr("i", 12);
  const bool sample_flag = cmd.isSet("sample");

  const string IP = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 PORT = cmd.getOr<u64>("port", 1212);

  if ((intersection_size > num_s) | (intersection_size > num_r)) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  spdlog::info("[psi_sp_ish] dim: {}, delta: {}, n_s: {}-{}, n_r: {}-{} ", DIM,
               DELTA, num_s_log, num_s, num_r_log, num_r);

  vector<pt> send_pts(num_s, vector<u64>(DIM, 0));
  vector<pt> recv_pts(num_r, vector<u64>(DIM, 0));

  sample_points(DIM, DELTA, num_s, num_r, intersection_size, send_pts, recv_pts,
                sample_flag);

  ipcl::initializeContext("QAT");
  ipcl::KeyPair psi_key = ipcl::generateKeypair(2048, true);
  ipcl::terminateContext();

  vector<coproto::Socket> socketPair0, socketPair1;
  // auto init_socks = [&](Role role) {
  //   for (u64 i = 0; i < THREAD_NUM; ++i) {
  //     auto port_temp = PORT + i;
  //     auto addr = IP + ":" + std::to_string(port_temp);
  //     if (role == Role::Sender) {
  //       socketPair0.push_back(coproto::asioConnect(addr, true));
  //     } else {
  //       socketPair1.push_back(coproto::asioConnect(addr, false));
  //     }
  //   }
  // };
  // std::thread recv_socks(init_socks, Role::Recv);
  // std::thread sender_socks(init_socks, Role::Sender);

  // recv_socks.join();
  // sender_socks.join();

  coproto::LocalAsyncSocket local_socket;
  auto pair_sock = local_socket.makePair();
  socketPair0.push_back(pair_sock[0]);
  socketPair1.push_back(pair_sock[1]);

  tVar timer;
  tStart(timer);

  PsiSpRecvISH recv_party(DIM, DELTA, num_r, num_s, THREAD_NUM, psi_key.pub_key,
                          psi_key.priv_key, recv_pts, socketPair0);
  PsiSpSenderISH sender_party(DIM, DELTA, num_s, num_r, THREAD_NUM,
                              psi_key.pub_key, psi_key.priv_key, send_pts,
                              socketPair1);

  recv_party.offline();
  sender_party.offline();

  auto offline_time = tEnd(timer);

  tStart(timer);
  std::thread recv_hash_online(std::bind(&PsiSpRecvISH::online, &recv_party));
  std::thread sender_hash_online(
      std::bind(&PsiSpSenderISH::online, &sender_party));

  recv_hash_online.join();
  sender_hash_online.join();
  auto online_time = tEnd(timer);
  auto com = socketPair0[0].bytesSent() + socketPair1[0].bytesSent();

  spdlog::debug("count: {}", recv_party.psi_ca_result);
  auto online_time_s_100 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 11;
  auto online_time_s_10 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 1.1;

  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_100, com,
               com / 1024.0 / 1024.0);
  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_10, com,
               com / 1024.0 / 1024.0);
}

void run_psi_sp_nonish(const oc::CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 10);
  const u64 THREAD_NUM = 1;
  const u64 num_s = 1ull << cmd.getOr("s", 18);
  const u64 num_s_log = cmd.getOr("s", 18);
  const u64 num_r = 1ull << cmd.getOr("r", 5);
  const u64 num_r_log = cmd.getOr("r", 5);
  const u64 intersection_size = cmd.getOr("i", 12);
  const bool sample_flag = cmd.isSet("sample");
  const bool sigma_flag = cmd.isSet("sigma");

  const string IP = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 PORT = cmd.getOr<u64>("port", 1212);

  if ((intersection_size > num_s) | (intersection_size > num_r)) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  spdlog::info("[psi_sp_nonish] dim: {}, delta: {}, n_s: {}-{}, n_r: {}-{} ",
               DIM, DELTA, num_s_log, num_s, num_r_log, num_r);

  vector<pt> send_pts(num_s, vector<u64>(DIM, 0));
  vector<pt> recv_pts(num_r, vector<u64>(DIM, 0));

  sample_points(DIM, DELTA, num_s, num_r, intersection_size, send_pts, recv_pts,
                sample_flag);

  ipcl::initializeContext("QAT");
  ipcl::KeyPair psi_key = ipcl::generateKeypair(2048, true);
  ipcl::terminateContext();

  vector<coproto::Socket> socketPair0, socketPair1;
  // auto init_socks = [&](Role role) {
  //   for (u64 i = 0; i < THREAD_NUM; ++i) {
  //     auto port_temp = PORT + i;
  //     auto addr = IP + ":" + std::to_string(port_temp);
  //     if (role == Role::Sender) {
  //       socketPair0.push_back(coproto::asioConnect(addr, true));
  //     } else {
  //       socketPair1.push_back(coproto::asioConnect(addr, false));
  //     }
  //   }
  // };
  // std::thread recv_socks(init_socks, Role::Recv);
  // std::thread sender_socks(init_socks, Role::Sender);

  // recv_socks.join();
  // sender_socks.join();

  coproto::LocalAsyncSocket local_socket;
  auto pair_sock = local_socket.makePair();
  socketPair0.push_back(pair_sock[0]);
  socketPair1.push_back(pair_sock[1]);

  tVar timer;
  tStart(timer);

  PsiSpRecvNonISH recv_party(DIM, DELTA, num_r, num_s, THREAD_NUM,
                             psi_key.pub_key, psi_key.priv_key, recv_pts,
                             sigma_flag, socketPair0);
  PsiSpSenderNonISH sender_party(DIM, DELTA, num_s, num_r, THREAD_NUM,
                                 psi_key.pub_key, psi_key.priv_key, send_pts,
                                 sigma_flag, socketPair1);

  recv_party.offline();
  sender_party.offline();
  auto offline_time = tEnd(timer);

  tStart(timer);
  std::thread recv_hash_online(
      std::bind(&PsiSpRecvNonISH::online, &recv_party));
  std::thread sender_hash_online(
      std::bind(&PsiSpSenderNonISH::online, &sender_party));

  recv_hash_online.join();
  sender_hash_online.join();
  auto online_time = tEnd(timer);
  auto com = socketPair0[0].bytesSent() + socketPair1[0].bytesSent();

  spdlog::debug("count: {}", recv_party.psi_ca_result);

  auto online_time_s_100 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 11;
  auto online_time_s_10 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 1.1;

  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_100, com,
               com / 1024.0 / 1024.0);
  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_10, com,
               com / 1024.0 / 1024.0);
}

void run_psi_ishash(const oc::CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 10);
  const u64 THREAD_NUM = 1;
  const u64 num_s = 1ull << cmd.getOr("s", 5);
  const u64 num_s_log = cmd.getOr("s", 5);
  const u64 num_r = 1ull << cmd.getOr("r", 18);
  const u64 num_r_log = cmd.getOr("r", 18);
  const u64 intersection_size = cmd.getOr("i", 12);
  const bool sample_flag = cmd.isSet("sample");
  const bool sigma_flag = cmd.isSet("sigma");

  const string IP = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 PORT = cmd.getOr<u64>("port", 1212);

  if ((intersection_size > num_s) | (intersection_size > num_r)) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  spdlog::info("[psi_ish] dim: {}, delta: {}, n_s: {}-{}, n_r: {}-{} ", DIM,
               DELTA, num_s_log, num_s, num_r_log, num_r);

  vector<pt> send_pts(num_s, vector<u64>(DIM, 0));
  vector<pt> recv_pts(num_r, vector<u64>(DIM, 0));

  sample_points(DIM, DELTA, num_s, num_r, intersection_size, send_pts, recv_pts,
                sample_flag);

  ipcl::initializeContext("QAT");
  ipcl::KeyPair psi_key = ipcl::generateKeypair(2048, true);
  ipcl::terminateContext();

  vector<coproto::Socket> socketPair0, socketPair1;
  // auto init_socks = [&](Role role) {
  //   for (u64 i = 0; i < THREAD_NUM; ++i) {
  //     auto port_temp = PORT + i;
  //     auto addr = IP + ":" + std::to_string(port_temp);
  //     if (role == Role::Sender) {
  //       socketPair0.push_back(coproto::asioConnect(addr, true));
  //     } else {
  //       socketPair1.push_back(coproto::asioConnect(addr, false));
  //     }
  //   }
  // };
  // std::thread recv_socks(init_socks, Role::Recv);
  // std::thread sender_socks(init_socks, Role::Sender);

  // recv_socks.join();
  // sender_socks.join();

  coproto::LocalAsyncSocket local_socket;
  auto pair_sock = local_socket.makePair();
  socketPair0.push_back(pair_sock[0]);
  socketPair1.push_back(pair_sock[1]);

  tVar timer;
  tStart(timer);

  PsiRecvISH recv_party(DIM, DELTA, num_r, num_s, THREAD_NUM, psi_key.pub_key,
                        psi_key.priv_key, recv_pts, socketPair1);

  PsiSenderISH sender_party(DIM, DELTA, num_s, num_r, THREAD_NUM,
                            psi_key.pub_key, psi_key.priv_key, send_pts,
                            socketPair0);

  recv_party.offline();
  sender_party.offline();

  auto offline_time = tEnd(timer);

  tStart(timer);
  std::thread recv_online(std::bind(&PsiRecvISH::online, &recv_party));
  std::thread sender_online(std::bind(&PsiSenderISH::online, &sender_party));

  recv_online.join();
  sender_online.join();

  auto online_time = tEnd(timer);
  auto com = socketPair0[0].bytesSent() + socketPair1[0].bytesSent();

  spdlog::debug("count: {}", recv_party.psi_ca_result);

  auto online_time_s_100 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 11;
  auto online_time_s_10 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 1.1;

  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_100, com,
               com / 1024.0 / 1024.0);
  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_10, com,
               com / 1024.0 / 1024.0);
}

void run_psi_nonish(const oc::CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 10);
  const u64 THREAD_NUM = 1;
  const u64 num_s = 1ull << cmd.getOr("s", 5);
  const u64 num_s_log = cmd.getOr("s", 5);
  const u64 num_r = 1ull << cmd.getOr("r", 18);
  const u64 num_r_log = cmd.getOr("r", 18);
  const u64 intersection_size = cmd.getOr("i", 12);
  const bool sample_flag = cmd.isSet("sample");
  const bool sigma_flag = cmd.isSet("sigma");

  const string IP = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 PORT = cmd.getOr<u64>("port", 1212);

  if ((intersection_size > num_s) | (intersection_size > num_r)) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  spdlog::info("[psi_nonish] dim: {}, delta: {}, n_s: {}-{}, n_r: {}-{} ", DIM,
               DELTA, num_s_log, num_s, num_r_log, num_r);

  vector<pt> send_pts(num_s, vector<u64>(DIM, 0));
  vector<pt> recv_pts(num_r, vector<u64>(DIM, 0));

  sample_points(DIM, DELTA, num_s, num_r, intersection_size, send_pts, recv_pts,
                sample_flag);

  ipcl::initializeContext("QAT");
  ipcl::KeyPair psi_key = ipcl::generateKeypair(2048, true);
  ipcl::terminateContext();

  vector<coproto::Socket> socketPair0, socketPair1;
  // auto init_socks = [&](Role role) {
  //   for (u64 i = 0; i < THREAD_NUM; ++i) {
  //     auto port_temp = PORT + i;
  //     auto addr = IP + ":" + std::to_string(port_temp);
  //     if (role == Role::Sender) {
  //       socketPair0.push_back(coproto::asioConnect(addr, true));
  //     } else {
  //       socketPair1.push_back(coproto::asioConnect(addr, false));
  //     }
  //   }
  // };
  // std::thread recv_socks(init_socks, Role::Recv);
  // std::thread sender_socks(init_socks, Role::Sender);

  // recv_socks.join();
  // sender_socks.join();

  coproto::LocalAsyncSocket local_socket;
  auto pair_sock = local_socket.makePair();
  socketPair0.push_back(pair_sock[0]);
  socketPair1.push_back(pair_sock[1]);

  tVar timer;
  tStart(timer);

  PsiSenderNonISH sender_party(DIM, DELTA, num_s, num_r, THREAD_NUM,
                               psi_key.pub_key, psi_key.priv_key, send_pts,
                               sigma_flag, socketPair0);
  PsiRecvNonISH recv_party(DIM, DELTA, num_r, num_s, THREAD_NUM,
                           psi_key.pub_key, psi_key.priv_key, recv_pts,
                           sigma_flag, socketPair1);

  sender_party.offline();
  recv_party.offline();
  auto offline_time = tEnd(timer);

  tStart(timer);
  std::thread sender_online(std::bind(&PsiSenderNonISH::online, &sender_party));
  std::thread recv_online(std::bind(&PsiRecvNonISH::online, &recv_party));

  sender_online.join();
  recv_online.join();
  auto online_time = tEnd(timer);
  auto com = socketPair0[0].bytesSent() + socketPair1[0].bytesSent();

  spdlog::debug("count: {}", recv_party.psi_ca_result);

  auto online_time_s_100 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 11;
  auto online_time_s_10 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 1.1;

  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_100, com,
               com / 1024.0 / 1024.0);
  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_10, com,
               com / 1024.0 / 1024.0);
}

void run_oprf_ish(const oc::CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 10);
  const u64 THREAD_NUM = 1;
  const u64 num_p1 = 1ull << cmd.getOr("p1", 18);
  const u64 num_p2 = 1ull << cmd.getOr("p2", 5);
  const u64 intersection_size = cmd.getOr("i", 12);
  const bool sample_flag = cmd.isSet("sample");

  const string IP = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 PORT = cmd.getOr<u64>("port", 1212);

  if ((intersection_size > num_p1) | (intersection_size > num_p2)) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  vector<pt> send_pts(num_p1, vector<u64>(DIM, 0));
  vector<pt> recv_pts(num_p2, vector<u64>(DIM, 0));

  sample_points(DIM, DELTA, num_p1, num_p2, intersection_size, send_pts,
                recv_pts, sample_flag);

  vector<coproto::Socket> socketPair0, socketPair1;
  // auto init_socks = [&](Role role) {
  //   for (u64 i = 0; i < THREAD_NUM; ++i) {
  //     auto port_temp = PORT + i;
  //     auto addr = IP + ":" + std::to_string(port_temp);
  //     if (role == Role::Sender) {
  //       socketPair0.push_back(coproto::asioConnect(addr, true));
  //     } else {
  //       socketPair1.push_back(coproto::asioConnect(addr, false));
  //     }
  //   }
  // };

  // std::thread recv_socks(init_socks, Role::Recv);
  // std::thread sender_socks(init_socks, Role::Sender);

  // recv_socks.join();
  // sender_socks.join();

  coproto::LocalAsyncSocket local_socket;
  auto pair_sock = local_socket.makePair();
  socketPair0.push_back(pair_sock[0]);
  socketPair1.push_back(pair_sock[1]);

  spdlog::info("[oprf ish] dim: {}, delta: {}, num_p1: {}, num_p2: {}", DIM,
               DELTA, num_p1, num_p2);

  tVar timer;
  tStart(timer);

  ShashOprfP1 p1_party(DIM, DELTA, num_p1, num_p2, THREAD_NUM, recv_pts,
                       socketPair0);
  ShashOprfP2 p2_party(DIM, DELTA, num_p2, num_p1, THREAD_NUM, send_pts,
                       socketPair1);

  p1_party.offline_hash();
  p2_party.offline_hash();

  auto offline_time = tEnd(timer);

  tStart(timer);
  std::thread p2_hash_online(std::bind(&ShashOprfP2::online_hash, &p2_party));
  std::thread p1_hash_online(std::bind(&ShashOprfP1::online_hash, &p1_party));

  p2_hash_online.join();
  p1_hash_online.join();
  auto online_time = tEnd(timer);
  auto com = socketPair0[0].bytesSent() + socketPair1[0].bytesSent();

  auto online_time_s_100 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 11;
  auto online_time_s_10 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 1.1;

  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_100, com,
               com / 1024.0 / 1024.0);
  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_10, com,
               com / 1024.0 / 1024.0);
}

void run_ahe_ish(const oc::CLP &cmd) {
  const u64 DIM = cmd.getOr("d", 2);
  const u64 DELTA = cmd.getOr("delta", 10);
  const u64 THREAD_NUM = 1;
  const u64 num_p1 = 1ull << cmd.getOr("p1", 18);
  const u64 num_p2 = 1ull << cmd.getOr("p2", 5);
  const u64 intersection_size = cmd.getOr("i", 12);
  const bool sample_flag = cmd.isSet("sample");

  const string IP = cmd.getOr<string>("ip", "127.0.0.1");
  const u64 PORT = cmd.getOr<u64>("port", 1212);

  if ((intersection_size > num_p1) | (intersection_size > num_p2)) {
    spdlog::error("intersection_size should not be greater than set_size");
    return;
  }

  vector<pt> send_pts(num_p1, vector<u64>(DIM, 0));
  vector<pt> recv_pts(num_p2, vector<u64>(DIM, 0));

  sample_points(DIM, DELTA, num_p1, num_p2, intersection_size, send_pts,
                recv_pts, sample_flag);

  ipcl::initializeContext("QAT");
  ipcl::KeyPair psi_key = ipcl::generateKeypair(2048, true);
  ipcl::terminateContext();

  vector<coproto::Socket> socketPair0, socketPair1;
  // auto init_socks = [&](Role role) {
  //   for (u64 i = 0; i < THREAD_NUM; ++i) {
  //     auto port_temp = PORT + i;
  //     auto addr = IP + ":" + std::to_string(port_temp);
  //     if (role == Role::Sender) {
  //       socketPair0.push_back(coproto::asioConnect(addr, true));
  //     } else {
  //       socketPair1.push_back(coproto::asioConnect(addr, false));
  //     }
  //   }
  // };

  // std::thread recv_socks(init_socks, Role::Recv);
  // std::thread sender_socks(init_socks, Role::Sender);

  // recv_socks.join();
  // sender_socks.join();

  coproto::LocalAsyncSocket local_socket;
  auto pair_sock = local_socket.makePair();
  socketPair0.push_back(pair_sock[0]);
  socketPair1.push_back(pair_sock[1]);

  spdlog::info("[ahe ish] dim: {}, delta: {}, num_p1: {}, num_p2: {}", DIM,
               DELTA, num_p1, num_p2);

  vector<vector<vector<block>>> shash_encodings;

  tVar timer;
  tStart(timer);

  ShashAheP1 p1_party(DIM, DELTA, num_p1, num_p2, THREAD_NUM, psi_key.pub_key,
                      psi_key.priv_key, send_pts, socketPair0);
  ShashAheP2 p2_party(DIM, DELTA, num_p2, num_p1, THREAD_NUM, psi_key.pub_key,
                      psi_key.priv_key, recv_pts, socketPair1);

  p1_party.offline(shash_encodings);
  p2_party.offline();

  auto offline_time = tEnd(timer);

  tStart(timer);
  std::thread p1_online(
      std::bind(&ShashAheP1::online, &p1_party, shash_encodings));
  std::thread p2_online(
      std::bind(&ShashAheP2::online, &p2_party, shash_encodings));

  p1_online.join();
  p2_online.join();
  auto online_time = tEnd(timer);
  auto com = socketPair0[0].bytesSent() + socketPair1[0].bytesSent();

  auto online_time_s_100 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 11;
  auto online_time_s_10 = online_time / 1000.0 + com / 1024.0 / 1024.0 / 1.1;

  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_100, com,
               com / 1024.0 / 1024.0);
  spdlog::info("offline time: {} s , online time: {} s; com: {} bytes, {} MB",
               offline_time / 1000.0, online_time_s_10, com,
               com / 1024.0 / 1024.0);
}