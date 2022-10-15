#define _CRT_SECURE_NO_WARNINGS

#include "seal/seal.h"
#include "sodium.h"

#include "bloomfilter.h"
#include "cmdline.h"
#include "examples.h" // print_parameter
#include "sodium.h"
#include "util.h"

#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace std;
using namespace seal;

int main(int argc, char *argv[]) {

  cmdline::parser cmd_parser;
  cmd_parser.add<string>("host", 'h', "ip of server", false, "127.0.0.1");
  cmd_parser.add<uint16_t>("port", 'p', "port of server", false, 51022,
                           cmdline::range(1, 65535));

  cmd_parser.add<uint64_t>("xa", 'x', "coordinate1 of client", false, 123456789,
                           cmdline::range(0ul, 1ul << 27)); // 134217728
  cmd_parser.add<uint64_t>("ya", 'y', "coordinate2 of client", false, 132456888,
                           cmdline::range(0ul, 1ul << 27)); // 134217728

  cmd_parser.add<size_t>("plain_modulus_bits", 'b',
                         "bit length of plain modulus", false, 56,
                         cmdline::range(1, 56));

  cmd_parser.add<uint64_t>("radius", 'r', "radius/thershold", false, 128,
                           cmdline::range(1, 8192));

  cmd_parser.add<size_t>("poly_modulus_degree", 'd',
                         "set degree of polynomial(2^d)", false, 13,
                         cmdline::range(12, 15));

  cmd_parser.parse_check(argc, argv);

  // radius
  string ip = cmd_parser.get<string>("host");
  uint16_t port = cmd_parser.get<uint16_t>("port");

  uint64_t xa = cmd_parser.get<uint64_t>("xa");
  uint64_t ya = cmd_parser.get<uint64_t>("ya");

  uint64_t radius = cmd_parser.get<uint64_t>("radius");
  // uint64_t sq_radius = radius * radius;

  uint64_t u = xa * xa + ya * ya;

  size_t poly_modulus_degree_bits =
      cmd_parser.get<size_t>("poly_modulus_degree"); // 4096 * 8
  size_t plain_modulus_bits = cmd_parser.get<size_t>("plain_modulus_bits");

  // while (1) {
  int sockfd_server = connect_to_server(ip, port);
  if (sockfd_server < 0) // fail
    return 1;
  pplp_printf("Connected to the server,  proximity test start...\n");
  pplp_printf("Client's coordinates:\t(%" PRIu64 ", %" PRIu64 ")\n", xa, ya);
  pplp_printf("Radius(Threshold):\t\t\t%" PRIu64 "\n", radius);

  auto t0 = chrono::high_resolution_clock::now();
  // vector<vector<chrono::time_point<system_clock, duration>>>

  // set the parms
  EncryptionParameters parms(scheme_type::bfv);
  size_t poly_modulus_degree = 1ull << poly_modulus_degree_bits;
  size_t plain_modulus = 1ull << plain_modulus_bits;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(plain_modulus); // sq
  // set the context
  SEALContext context(parms);
  if (flag_log)
    print_parameters(context);
  pplp_printf("Parameter validation: %s\n", context.parameter_error_message());

  // generate sk and pk
  KeyGenerator keygen(context);
  SecretKey sk = keygen.secret_key();
  PublicKey pk;
  keygen.create_public_key(pk);

  auto t1 = chrono::high_resolution_clock::now();

  // encrypt the data
  Ciphertext c1, c2, c3;
  Encryptor encryptor(context, pk);
  encryptor.encrypt(Plaintext(uint64_to_hex_string(u)), c1);
  encryptor.encrypt(Plaintext(uint64_to_hex_string(xa << 1)), c2);
  encryptor.encrypt(Plaintext(uint64_to_hex_string(ya << 1)), c3);

  auto t2 = chrono::high_resolution_clock::now();

  // send the parms to the server
  stringstream stream_parms;
  parms.save(stream_parms);
  // cout << stream_parms.str() << endl;
  ssize_t bytes = send(sockfd_server, stream_parms.str().c_str(),
                       stream_parms.str().length(), 0);
  cout << "Send parms(context) to the server, bytes: " << bytes << endl;

  auto t3 = chrono::high_resolution_clock::now();

  // // send the pk to the server ????????????????????????????????
  // stringstream stream_pk;
  // pk.save(stream_pk);
  // bytes_to_send(sockfd_server, stream_pk.str().length());
  // bytes =
  //     send(sockfd_server, stream_pk.str().c_str(), stream_pk.str().length(),
  //     0);
  // cout << "Send the public key to the server, bytes: " << bytes << endl;

  // send the encrypted data the server
  auto t4 = chrono::high_resolution_clock::now();

  stringstream stream_cipher;
  c1.save(stream_cipher);
  bytes_to_send(sockfd_server, stream_cipher.str().length());
  bytes = send(sockfd_server, stream_cipher.str().c_str(),
               stream_cipher.str().length(), 0);
  cout << "Send the ciphertext 1 to the server, bytes: " << bytes << endl;

  auto t5 = chrono::high_resolution_clock::now();

  stream_cipher.clear();
  stream_cipher.str(string());
  c2.save(stream_cipher);
  bytes_to_send(sockfd_server, stream_cipher.str().length());
  bytes = send(sockfd_server, stream_cipher.str().c_str(),
               stream_cipher.str().length(), 0);
  cout << "Send the ciphertext 2 to the server, bytes: " << bytes << endl;

  auto t6 = chrono::high_resolution_clock::now();

  stream_cipher.clear();
  stream_cipher.str(string());
  c3.save(stream_cipher);
  bytes_to_send(sockfd_server, stream_cipher.str().length());
  bytes = send(sockfd_server, stream_cipher.str().c_str(),
               stream_cipher.str().length(), 0);
  cout << "Send the ciphertext 3 to the server, bytes: " << bytes << endl;

  auto t7 = chrono::high_resolution_clock::now();

  // receive the bloom filter from server
  bytes = bytes_to_receive(sockfd_server);
  ssize_t bytes_tmp = bytes;
  uint8_t *bf_buf = (uint8_t *)malloc(bytes);
  uint8_t *p_bf_buf = bf_buf;
  while (bytes != 0) {
    ssize_t cur_bytes = recv(sockfd_server, p_bf_buf, bytes, 0);
    p_bf_buf += cur_bytes;
    bytes -= cur_bytes;
  }
  uint64_t w = *(uint64_t *)bf_buf;
  bloom_filter bf(bf_buf + sizeof(uint64_t));
  free(bf_buf);
  cout << "Receive the BF from the server, bytes: " << bytes_tmp << endl;

  auto t8 = chrono::high_resolution_clock::now();

  // receive the encrypted data from the server
  Ciphertext cipher_blind_distance;
  stream_cipher.clear();
  stream_cipher.str(string());
  bytes = bytes_to_receive(sockfd_server);
  bytes_tmp = bytes;
  while (bytes != 0) {
    memset(buf, 0, sizeof(buf));
    ssize_t cur_bytes = recv(sockfd_server, buf, sizeof(buf), 0);
    stream_cipher << string(buf, cur_bytes);
    bytes -= cur_bytes;
  }
  cipher_blind_distance.load(context, stream_cipher);
  cout << "Receive the encrypted data from the server, bytes: " << bytes_tmp
       << endl;

  auto t9 = chrono::high_resolution_clock::now();

  // decrypt the result to get the blind distance
  Decryptor decryptor(context, sk);
  Plaintext plain_blind_distance;
  decryptor.decrypt(cipher_blind_distance, plain_blind_distance);

  uint64_t blind_distance =
      hex_string_to_uint(plain_blind_distance.to_string());
  cout << "blind_distance: " << blind_distance << endl;
  bool isNear = bf.contains((blind_distance << get_bitlen(w)) | w);

  // auto t9 = chrono::high_resolution_clock::now();

  // auto time_keygen =
  //     chrono::duration_cast<chrono::nanoseconds>(t1 - t0);
  // auto time_init =
  //     chrono::duration_cast<chrono::nanoseconds>(t1 - t0);

  // auto time_calc = ;
  // auto time_total = ;

  auto elapsed = chrono::duration_cast<chrono::nanoseconds>(t7 - t0);
  cout << (isNear ? "near" : "far") << endl;
  printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
  cout << endl;
  close(sockfd_server);
  // }
  return 0;
}