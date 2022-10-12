#include <sodium/randombytes.h>
#define _CRT_SECURE_NO_WARNINGS

#include "bloomfilter.h"
#include "cmdline.h"
#include "examples.h" // print_parameter
#include "seal/seal.h"
#include "sodium.h"
#include "util.h"

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

using namespace std;
using namespace seal;

int main(int argc, char *argv[]) {

  cmdline::parser cmd_parser;

  cmd_parser.add<uint64_t>("xa", 'x', "coordinate1 of client", false, 1234,
                           cmdline::range(0ul, 1ul << 27)); // 134217728
  cmd_parser.add<uint64_t>("ya", 'y', "coordinate2 of client", false, 1212,
                           cmdline::range(0ul, 1ul << 27)); // 134217728

  cmd_parser.add<uint64_t>("xb", 'u', "coordinate1 of server", false, 1000,
                           cmdline::range(0ul, 1ul << 27)); // 134217728
  cmd_parser.add<uint64_t>("yb", 'v', "coordinate2 of server", false, 1000,
                           cmdline::range(0ul, 1ul << 27)); // 134217728

  cmd_parser.add<uint64_t>("radius", 'r', "radius/thershold", false, 128,
                           cmdline::range(1, 8192));

  cmd_parser.add<size_t>("plain_modulus_bits", 'b',
                         "bit length of plain modulus", false, 56,
                         cmdline::range(1, 56));

  cmd_parser.add<size_t>("poly_modulus_degree", 'd',
                         "set degree of polynomial(2^d)", false, 13,
                         cmdline::range(12, 15));

  cmd_parser.parse_check(argc, argv);

  // debug
  Plaintext pdbg;
  uint64_t xa = cmd_parser.get<uint64_t>("xa");
  uint64_t ya = cmd_parser.get<uint64_t>("ya");
  uint64_t xb = cmd_parser.get<uint64_t>("xb");
  uint64_t yb = cmd_parser.get<uint64_t>("yb");

  uint64_t radius = cmd_parser.get<uint64_t>("radius");
  uint64_t sq_radius = radius * radius;

  pplp_printf("Client's coordinates:\t(%" PRIu64 ", %" PRIu64 ")\n", xa, ya);
  pplp_printf("Server's coordinates:\t(%" PRIu64 ", %" PRIu64 ")\n", xb, yb);
  pplp_printf("Radius(Threshold):\t\t\t%" PRIu64 "\n", radius);

  auto begin = std::chrono::high_resolution_clock::now();
  // A  KeyGen
  EncryptionParameters parms(scheme_type::bfv);
  size_t poly_modulus_degree_bits =
      cmd_parser.get<size_t>("poly_modulus_degree"); // 4096 * 8
  size_t plain_modulus_bits = cmd_parser.get<size_t>("plain_modulus_bits");
  size_t poly_modulus_degree = 1ull << poly_modulus_degree_bits;
  size_t plain_modulus = 1ull << plain_modulus_bits;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(plain_modulus); // sq

  SEALContext context(parms);
  print_parameters(context);
  cout << "Parameter validation (success): "
       << context.parameter_error_message() << endl;

  KeyGenerator keygen(context);
  SecretKey secret_key = keygen.secret_key();
  PublicKey public_key;
  keygen.create_public_key(public_key);

  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);
  Decryptor decryptor(context, secret_key);
  RelinKeys relin_keys;
  keygen.create_relin_keys(relin_keys);

  // B initialize bloom filter
  bloom_parameters bf_parms;
  bf_parms.projected_element_count = sq_radius;
  bf_parms.false_positive_probability = 0.0001; // 1 in 10000
  bf_parms.random_seed = 0xA5A5A5A5;
  bf_parms.compute_optimal_parameters();
  bloom_filter bf(bf_parms);

  // insert key-hashed blind distance
  int sq_len = get_bitlen(sq_radius);
  uint64_t r = randombytes_uniform(56 - sq_len);
  uint64_t s = randombytes_uniform(sq_len);
  uint64_t w = randombytes_uniform(256);
  int w_len = get_bitlen(w);
  for (uint64_t di = 0; di < sq_radius; ++di) {
    uint64_t bd = s * (di + r);
    bf.insert((bd << uint64_t(w_len)) | w);
  }

  Ciphertext cr;
  encryptor.encrypt(Plaintext(uint64_to_hex_string(r * s)), cr);

  // A ---------------
  uint64_t u = xa * xa + ya * ya;
  Ciphertext c1, c2, c3;
  Plaintext p1(uint64_to_hex_string(u));
  Plaintext p2(uint64_to_hex_string(xa << 1));
  Plaintext p3(uint64_to_hex_string(ya << 1));

  encryptor.encrypt(p1, c1);
  encryptor.encrypt(p2, c2);
  encryptor.encrypt(p3, c3);

  // B ----------------
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

  // A ----------------------
  Plaintext plain_blind_distance;
  decryptor.decrypt(c1, plain_blind_distance);

  uint64_t blind_distance =
      hex_string_to_uint(plain_blind_distance.to_string());
  cout << "blind_distance: " << blind_distance << endl;

  bool isNear = bf.contains((blind_distance << uint64_t(w_len)) | w);
  auto end = std::chrono::high_resolution_clock::now();
  auto elapsed =
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

  cout << (isNear ? "near" : "far") << endl;
  printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
}
