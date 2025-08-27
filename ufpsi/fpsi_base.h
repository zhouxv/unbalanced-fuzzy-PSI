#pragma once
#include "config.h"
#include "utils/util.h"
#include <coproto/Socket/Socket.h>
#include <vector>

class FPSIBase {
public:
  explicit FPSIBase(vector<coproto::Socket> &sockets) : sockets(sockets) {}

  simpleTimer fpsi_timer;
  std::vector<std::pair<string, double>> commus;
  vector<coproto::Socket> &sockets;

  void print_time() { fpsi_timer.print(); }

  void merge_timer(simpleTimer &other) { fpsi_timer.merge(other); }

  void print_commus() {
    for (auto &x : commus) {
      spdlog::info("{}: {} MB", x.first, x.second);
    }
  }

  void insert_commus(const string &msg, u64 socket_index) {
    commus.push_back(
        {msg, sockets[socket_index].bytesSent() / 1024.0 / 1024.0});
    sockets[socket_index].mImpl->mBytesSent = 0;
  }

  virtual ~FPSIBase() = default;
};