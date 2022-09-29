#ifdef dbg
#define dbg_pc(ct, log) {Plaintext pdbg; decryptor.decrypt ((ct), (pdbg)); cout << (log) << (pdbg).to_string () << endl;}
#define dbg_pp(val, log) {cout<<(log)<<(val)<<end;}
#else
#define dbg_pc(ct, log) 1
#define dbg_pp(pt, log) 1
#endif

int
get_bitlen (uint64_t x)
{
  // 0 is 1 bit...
  int ret = 1;
  while (x >>= 1)
    ++ret;
  return ret;
}