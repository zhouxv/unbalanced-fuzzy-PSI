#pragma once

#include <cryptoTools/Common/CLP.h>
#include <cryptoTools/Common/Defines.h>

using namespace oc;

enum class Role { Recv, Sender };

void run_psi_sp_ishash(const oc::CLP &cmd);

void run_psi_sp_nonish(const oc::CLP &cmd);

void run_psi_ishash(const oc::CLP &cmd);

void run_psi_nonish(const oc::CLP &cmd);

void run_oprf_ish(const oc::CLP &cmd);

void run_ahe_ish(const oc::CLP &cmd);