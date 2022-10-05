
// for non-interactive only
#ifdef dbg
#define dbg_pc(ct, log)                          \
  {                                              \
    Plaintext pdbg;                              \
    decryptor.decrypt((ct), (pdbg));             \
    cout << (log) << (pdbg).to_string() << endl; \
  }
#define dbg_pp(val, log)           \
  {                                \
    cout << (log) << (val) << end; \
  }
#else
#define dbg_pc(ct, log) 1
#define dbg_pp(pt, log) 1
#endif

size_t get_bitlen(uint64_t x)
{
  // 0 is 1 bit...
  size_t ret = 1;
  while (x >>= 1)
    ++ret;
  return ret;
}

// radius
uint64_t th = 512;
uint64_t sq_threshold = th * th;
// run client and server in locally
uint16_t local_test_port = 51022;