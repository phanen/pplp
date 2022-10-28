

#ifndef __PPLP_H_
#define __PPLP_H_

#include "../../abycore/aby/abyparty.h"
#include "../../abycore/circuit/arithmeticcircuits.h"
#include "../../abycore/circuit/booleancircuits.h"
#include "../../abycore/circuit/circuit.h"
#include <cassert>
#include <math.h>

#define ALICE "ALICE"
#define BOB "BOB"

int32_t test_pplp_circuit (e_role role, const std::string &address,
                           uint16_t port, seclvl seclvl, uint32_t bitlen,
                           uint32_t nthreads, e_mt_gen_alg mt_alg,
                           e_sharing sharing, uint32_t thr);

share *BuildPPLPCircuit (size_t edges, share **x, share **y, share **z,
                         share *xp, share *yp, share *thr, Circuit *circA,
                         BooleanCircuit *circY);

#endif /* __PPLP_H_ */
