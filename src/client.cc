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

  cmd_parser.add<uint64_t>("xa", 'x', "coordinate1 of client", false, 1234,
                           cmdline::range(0ul, UINT64_MAX));
  cmd_parser.add<uint64_t>("ya", 'y', "coordinate2 of client", false, 1212,
                           cmdline::range(0ul, UINT64_MAX));

  cmd_parser.add<size_t>("plain_modulus_bits", 'b',
                         "bit length of plain modulus", false, 56,
                         cmdline::range(1, 56));

  cmd_parser.add<size_t>("poly_modulus_degree", 'd',
                         "set degree of polynomial(2^d)", false, 13,
                         cmdline::range(12, 15));

  cmd_parser.parse_check(argc, argv);

  // radius
  string ip = cmd_parser.get<string>("host");
  uint16_t port = cmd_parser.get<uint16_t>("port");

  uint64_t xa = cmd_parser.get<uint64_t>("xa");
  uint64_t ya = cmd_parser.get<uint64_t>("ya");
  // uint64_t radius = cmd_parser.get<uint64_t>("radius");
  // uint64_t sq_radius = radius * radius;

  uint64_t u = xa * xa + ya * ya;
  Plaintext p1(uint64_to_hex_string(u));
  Plaintext p2(uint64_to_hex_string(xa << 1));
  Plaintext p3(uint64_to_hex_string(ya << 1));

  pplp_printf("Client's coordinates:\t(%" PRIu64 ", %" PRIu64 ")\n", xa, ya);
  pplp_printf("Radius(Threshold):\t\t\t%" PRIu64 "\n", th);

  int sockfd_server = connect_to_server(ip, port);
  pplp_printf("Connected to the server,  proximity test start...\n");

  auto t1 = std::chrono::high_resolution_clock::now();

  // set the parms
  EncryptionParameters parms(scheme_type::bfv);
  size_t poly_modulus_degree = 4096;     // 4096 * 8
  uint64_t plain_modulus_bit_count = 33; // 56
  uint64_t plain_modulus = 1ull << plain_modulus_bit_count;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(plain_modulus);

  // set the context
  SEALContext context(parms);
  if (flag_log)
    print_parameters(context);
  cout << "Parameter validation (success): "
       << context.parameter_error_message() << endl;

  // generate sk and pk
  KeyGenerator keygen(context);
  SecretKey sk = keygen.secret_key();
  PublicKey pk;
  keygen.create_public_key(pk);

  // send the parms to the server
  std::stringstream stream_parms;
  parms.save(stream_parms);
  // cout << stream_parms.str() << endl;
  ssize_t bytes = send(sockfd_server, stream_parms.str().c_str(),
                       stream_parms.str().length(), 0);
  cout << "Send parms(context) to the server, bytes: " << bytes << endl;

  // send the pk to the server
  std::stringstream stream_pk;
  pk.save(stream_pk);
  bytes_to_send(sockfd_server, stream_pk.str().length());
  bytes =
      send(sockfd_server, stream_pk.str().c_str(), stream_pk.str().length(), 0);
  cout << "Send the public key to the server, bytes: " << bytes << endl;

  // encrypt the data
  Encryptor encryptor(context, pk);
  Ciphertext c1, c2, c3;
  encryptor.encrypt(p1, c1);
  encryptor.encrypt(p2, c2);
  encryptor.encrypt(p3, c3);

  // send the encrypted data the server
  std::stringstream stream_cipher;
  c1.save(stream_cipher);
  bytes_to_send(sockfd_server, stream_cipher.str().length());
  bytes = send(sockfd_server, stream_cipher.str().c_str(),
               stream_cipher.str().length(), 0);
  cout << "Send the ciphertext 1 to the server, bytes: " << bytes << endl;

  stream_cipher.clear();
  stream_cipher.str(std::string());
  c2.save(stream_cipher);
  bytes_to_send(sockfd_server, stream_cipher.str().length());
  bytes = send(sockfd_server, stream_cipher.str().c_str(),
               stream_cipher.str().length(), 0);
  cout << "Send the ciphertext 2 to the server, bytes: " << bytes << endl;

  stream_cipher.clear();
  stream_cipher.str(std::string());
  c3.save(stream_cipher);
  bytes_to_send(sockfd_server, stream_cipher.str().length());
  bytes = send(sockfd_server, stream_cipher.str().c_str(),
               stream_cipher.str().length(), 0);
  cout << "Send the ciphertext 3 to the server, bytes: " << bytes << endl;

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

  // receive the encrypted data from the server
  Ciphertext cipher_blind_distance;
  stream_cipher.clear();
  stream_cipher.str(std::string());
  bytes = bytes_to_receive(sockfd_server);
  bytes_tmp = bytes;
  while (bytes != 0) {
    memset(buf, 0, sizeof(buf));
    ssize_t cur_bytes = recv(sockfd_server, buf, sizeof(buf), 0);
    stream_cipher << std::string(buf, cur_bytes);
    bytes -= cur_bytes;
  }
  cipher_blind_distance.load(context, stream_cipher);
  cout << "Receive the encrypted data from the server, bytes: " << bytes_tmp
       << endl;

  // decrypt the result to get the blind distance
  Decryptor decryptor(context, sk);
  Plaintext plain_blind_distance;
  decryptor.decrypt(cipher_blind_distance, plain_blind_distance);

  uint64_t blind_distance =
      hex_string_to_uint(plain_blind_distance.to_string());
  cout << "blind_distance: " << blind_distance << endl;
  bool isNear = bf.contains((blind_distance << get_bitlen(w)) | w);
  auto end = std::chrono::high_resolution_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - t1);

  cout << (isNear ? "near" : "far") << endl;
  std::printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
  cout << endl;
  close(sockfd_server);
  return 0;
}