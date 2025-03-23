# aby
Sharings: Underlying secure computation techniques
Circuits: A secure computation protocol evaluates a function

Gates
* high-level gate
* I/O gate
  * shr: PutINGate
  * res: PutOUTGate
* primitive gate
  * The linear gates can be evaluated locally
  * Reducing the number of **non-linear gates**

Shares
* Why
  * To simplify the design of circuits
  * Bundle one or multiple wires
* What
  * Array of `uint32_t` wire IDs
  * `bitlength`of share: size of array
* How
  * The input/output of Gate
  * To operate on wires: getter and setter

```cc
// Init ABYParty
ABYParty(e_role pid ,
         char* addr = (char *) "127.0.0.1",
         uint16_tport = 7766,
         seclvl = LT ,
         uint32_t bitlen = 32,
         uint32_t nthreads = 2,
         e_mt_gen_alg mg_algo = MT_OT,
         uint32_t maxgates = 4000000);
// GetSharings
vector <Sharing *>& sharings = party ->GetSharings ();
// GetCircuitBuildRoutine, sharing ∈ {S_ARITH, S_BOOL, S_YAO}
Circuit* circ = sharings[sharing]-> GetCircuitBuildRoutine ();

// Manually build the circuit
// ...

//  Execution
party ->ExecCircuit ();

// Besides
party->Reset();
delete party;
```
