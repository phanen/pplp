#define _CRT_SECURE_NO_WARNINGS

#include <chrono>
#include <iostream>
#include <set>
#include <vector>

#define dbg
#include "util.h"
#include "seal/seal.h"
#include "examples.h"
#include "bloomfilter.h"

using namespace std;
using namespace seal;

void pplp(int th_)
{
  // debug
  Plaintext pdbg;
  // A
  uint64_t xa = 217;
  uint64_t ya = 201;
  uint64_t xb = 201;
  uint64_t yb = 200;
  // uint64_t ya = 32123123;
  // uint64_t xa = 32123124;
  // uint64_t xb = 31005421;
  // uint64_t yb = 31005321;

  uint64_t th = 4096;
  uint64_t sq_threshold = th * th;
  uint64_t plain_modulus_bit_count = 33; // 56

  cout << "A's horizontal coordinates:\t" << xa << endl;
  cout << "A's vertical coordinates:\t" << ya << endl;
  cout << "B's horizontal coordinates:\t" << xb << endl;
  cout << "B's vertical coordinates:\t" << yb << endl;
  cout << "radius(threshold):\t" << th << endl;

  auto begin = std::chrono::high_resolution_clock::now();
  // A ---------------------- KeyGen
  EncryptionParameters parms(scheme_type::bfv);
  size_t poly_modulus_degree = 4096; // 4096 * 8
  uint64_t plain_modulus = 1ull << plain_modulus_bit_count;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(plain_modulus); // 0 -- 10, sq: 0 -- 100

  SEALContext context(parms);
  print_parameters(context);
  cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

  KeyGenerator keygen(context);
  SecretKey secret_key = keygen.secret_key();
  PublicKey public_key;
  keygen.create_public_key(public_key);

  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);
  RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);

  // B ---------------------- BF Insert
  // initialize bloom filter
  bloom_parameters bf_parms;
  bf_parms.projected_element_count = sq_threshold;
  bf_parms.false_positive_probability = 0.0001; // 1 in 10000
  bf_parms.random_seed = 0xA5A5A5A5;
  bf_parms.compute_optimal_parameters();
  bloom_filter bf(bf_parms);
  // insert key-hashed blind distance
  uint64_t r = 13, s = 17, w = 11;
  int w_len = get_bitlen(w);

  for (uint64_t di = 0; di < sq_threshold; ++di)
  {
    uint64_t bd = s * (di + r);
    // cout << bd << ' ';
    bf.insert((bd << uint64_t(w_len)) | w);
  }
  // cout << endl;

  Ciphertext cr;
  encryptor.encrypt(Plaintext(uint64_to_hex_string(r * s)), cr);
  dbg_pc(cr, "cr: ");

  // A ---------------
  uint64_t u = xa * xa + ya * ya;
  // dbg_pp (u, "u: ");

  Ciphertext c1, c2, c3;
  Plaintext p1(uint64_to_hex_string(u));
  Plaintext p2(uint64_to_hex_string(xa << 1));
  Plaintext p3(uint64_to_hex_string(ya << 1));
  cout << p1.to_string() << endl;
  cout << hex << u << endl;
  encryptor.encrypt(p1, c1);
  encryptor.encrypt(p2, c2);
  encryptor.encrypt(p3, c3);
  dbg_pc(c1, "c1: ");
  dbg_pc(c2, "c2: ");
  dbg_pc(c3, "c3: ");

  // B ---------------------
  uint64_t z = xb * xb + yb * yb;
  Plaintext plain_z(uint64_to_hex_string(z));
  Plaintext plain_xb(uint64_to_hex_string(xb));
  Plaintext plain_yb(uint64_to_hex_string(yb));

  evaluator.add_plain_inplace(c1, plain_z);
  evaluator.multiply_plain_inplace(c2, plain_xb);
  evaluator.multiply_plain_inplace(c3, plain_yb);
  evaluator.add_inplace(c2, c3);
  evaluator.sub_inplace(c1, c2);
  evaluator.multiply_plain_inplace(c1, Plaintext(uint64_to_hex_string(s)));
  evaluator.add_plain_inplace(c1, Plaintext(uint64_to_hex_string(s * r)));
  dbg_pc(c1, "c1: ");

  // A ----------------------
  Plaintext p_dis;
  decryptor.decrypt(c1, p_dis);

  cout << p_dis.to_string() << endl;
  uint64_t i_dis = hex_string_to_uint(p_dis.to_string());
  cout << "blind_distance: " << i_dis << endl;

  bool isNear = bf.contains((i_dis << uint64_t(w_len)) | w);
  auto end = std::chrono::high_resolution_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

  // //输出该密文的多项式个数
  // cout << "    + size of freshly encrypted x: " << c2.size() << endl;
  // //输出该密文还剩下的噪声预算
  // cout << "    + noise budget in freshly encrypted x: " << decryptor.invariant_noise_budget(c2) << " bits"
  //    << endl;

  cout << (isNear ? "near" : "far") << endl;
  printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
  cout << endl;
}