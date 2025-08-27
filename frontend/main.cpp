
#include "fpsi_protocol.h"
#include "test.h"

#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>

using namespace osuCrypto;

void print_usage() {
  std::cout << "Usage:";
  std::cout << "  --p <num>         select pro type (1-6):\n";
  std::cout << "      1: run_psi_sp_ishash\n";
  std::cout << "      2: run_psi_sp_nonish\n";
  std::cout << "      3: run_psi_ishash\n";
  std::cout << "      4: run_psi_nonish\n";
  std::cout << "      5: run_oprf_ish\n";
  std::cout << "      6: run_ahe_ish\n";
  std::cout << "  --test <num>      run test (1-6):\n";
  std::cout << "      1: test_ecc_elgamal\n";
  std::cout << "      2: test_oprf\n";
  std::cout << "      3: test_flat_and_recovery\n";
  std::cout << "      4: test_paxos_param\n";
  std::cout << "      5: test_intersection\n";
  std::cout << "      6: test_okvs\n";
  std::cout
      << "  --log <level>    log level  (0:off, 1:info, 2:debug, 3:debug)\n";
}

int main(int argc, char **argv) {
  CLP cmd;
  cmd.parse(argc, argv);

  auto log_level = cmd.getOr<u64>("log", 1);

  spdlog::set_pattern("[%l] %v");
  // spdlog::set_pattern("%v");
  switch (log_level) {
  case 0:
    spdlog::set_level(spdlog::level::off);
    break;
  case 1:
    spdlog::set_level(spdlog::level::info);
    break;
  case 2:
    spdlog::set_level(spdlog::level::debug);
    break;
  case 3:
    spdlog::set_level(spdlog::level::debug);
    break;
  default:
    spdlog::set_level(spdlog::level::info);
  }

  if (cmd.isSet("p")) {
    switch (cmd.getOr<u64>("p", 1)) {
    case 1:
      run_psi_sp_ishash(cmd);
      break;
    case 2:
      run_psi_sp_nonish(cmd);
      break;
    case 3:
      run_psi_ishash(cmd);
      break;
    case 4:
      run_psi_nonish(cmd);
      break;
    case 5:
      run_oprf_ish(cmd);
      break;
    case 6:
      run_ahe_ish(cmd);
      break;
    default:
      std::cout << "error protocol type";
    }

    return 0;
  }

  if (cmd.isSet("test")) {
    switch (cmd.getOr<u64>("test", 1)) {
    case 1:
      test_ecc_elgamal(cmd);
      break;
    case 2:
      test_oprf(cmd);
      break;
    case 3:
      test_flat_and_recovery(cmd);
    case 4:
      test_paxos_param(cmd);
      break;
    case 5:
      test_intersection(cmd);
      break;
    case 6:
      test_okvs(cmd);
      break;
    default:
      std::cout << "error test protocol type\n";
    }

    return 0;
  }

  print_usage();

  return 0;
}
