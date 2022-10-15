#define _CRT_SECURE_NO_WARNINGS

#include "seal/seal.h"
#include "sodium.h"

#include "bloomfilter.h"
#include "cmdline.h"
#include "examples.h" // print_parameter
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

  cmd_parser.add<uint64_t>("xb", 'u', "coordinate1 of server", false, 1000,
                           cmdline::range(0ul, 1ul << 27)); // 134217728
  cmd_parser.add<uint64_t>("yb", 'v', "coordinate2 of server", false, 1000,
                           cmdline::range(0ul, 1ul << 27)); // 134217728

  cmd_parser.add<uint64_t>("radius", 'r', "radius/thershold", false, 128,
                           cmdline::range(1, 8192));

  cmd_parser.add<uint64_t>("hkey", 'w', "hash key", false, 128,
                           cmdline::range(1, 8192));

  cmd_parser.add<uint64_t>("shift", 's', "shift", false, 128,
                           cmdline::range(1, 8192));

  cmd_parser.parse_check(argc, argv);

  string ip = cmd_parser.get<string>("host");
  uint16_t port = cmd_parser.get<uint16_t>("port");
  uint64_t xb = cmd_parser.get<uint64_t>("xb");
  uint64_t yb = cmd_parser.get<uint64_t>("yb");
  uint64_t radius = cmd_parser.get<uint64_t>("radius");

  uint64_t z = xb * xb + yb * yb;
  uint64_t sq_radius = radius * radius;

  pplp_printf("Server's coordinates:\t(%" PRIu64 ", %" PRIu64 ")\n", xb, yb);
  pplp_printf("Radius(Threshold):\t\t\t%" PRIu64 "\n", radius);

  // while (1) {
  // serve only one

  int sockfd_client = connect_to_client(ip, port);

  pplp_printf("proximity test start...\n");

  auto t1 = chrono::high_resolution_clock::now();

  // receive the parms from the client
  ssize_t bytes = recv(sockfd_client, buf, sizeof(buf), 0);
  cout << "Receive parms from the client, bytes: " << bytes << endl;

  // set the parms and the context
  EncryptionParameters parms;
  stringstream stream_parms;
  stream_parms << string((char *)buf, bytes);
  parms.load(stream_parms);
  SEALContext context(parms);

  if (flag_log)
    print_parameters(context);
  cout << "Parameter validation (success): "
       << context.parameter_error_message() << endl;

  // // receive the pk from the client
  // stringstream stream_pk;
  // bytes = bytes_to_receive(sockfd_client);
  // ssize_t bytes_tmp = bytes;
  // while (bytes != 0) {
  //   memset(buf, 0, sizeof(buf));
  //   ssize_t cur_bytes =
  //       recv(sockfd_client, buf, min(size_t(bytes), sizeof(buf)), 0);
  //   stream_pk << string((char *)buf, cur_bytes);
  //   bytes -= cur_bytes;
  // };
  // cout << "Receive the public key from the client, bytes: " << bytes_tmp
  //      << endl;
  // PublicKey pk;
  // pk.load(context, stream_pk);

  // set the bloom filter
  bloom_parameters bf_parms;
  bf_parms.projected_element_count = sq_radius;
  bf_parms.false_positive_probability = 0.0001; // 1 in 10000
  bf_parms.random_seed = 0xA5A5A5A5;
  bf_parms.compute_optimal_parameters();
  bloom_filter bf(bf_parms);
  // generate the random number
  int sq_len = get_bitlen(sq_radius);
  // uint64_t r = randombytes_uniform(56 - sq_len);
  // uint64_t s = randombytes_uniform(sq_len);
  // uint64_t w = randombytes_uniform(256);
  uint64_t r, s, w; // to fix

  r = 2;
  s = 3;
  w = cmd_parser.get<uint64_t>("hkey");
  int w_len = get_bitlen(w);
  for (uint64_t di = 0; di < sq_radius; ++di) {
    uint64_t bd = s * (di + r);
    bf.insert((bd << uint64_t(w_len)) | w);
  }

  // reveive the encrypted data from the client
  vector<Ciphertext> lst_cipher;
  // for each ciphertext
  for (size_t id_cipher = 0; id_cipher < 3; id_cipher++) {
    bytes = bytes_to_receive(sockfd_client);
    Ciphertext cipher_tmp;
    stringstream stream_cipher;
    ssize_t bytes_tmp = bytes;
    while (bytes != 0) {
      memset(buf, 0, sizeof(buf));
      ssize_t cur_bytes =
          recv(sockfd_client, buf, min(size_t(bytes), sizeof(buf)), 0);
      stream_cipher << string((char *)buf, cur_bytes);
      bytes -= cur_bytes;
    }
    cipher_tmp.load(context, stream_cipher);
    lst_cipher.push_back(cipher_tmp);
    cout << "Receive the ciphertext " << id_cipher + 1
         << " from the client, bytes: " << bytes_tmp << endl;
  }

  //  homomorphic evaluation
  Evaluator evaluator(context);
  Plaintext plain_z(uint64_to_hex_string(z));
  Plaintext plain_xb(uint64_to_hex_string(xb));
  Plaintext plain_yb(uint64_to_hex_string(yb));
  evaluator.add_plain_inplace(lst_cipher[0], plain_z);
  evaluator.multiply_plain_inplace(lst_cipher[1], plain_xb);
  evaluator.multiply_plain_inplace(lst_cipher[2], plain_yb);
  evaluator.add_inplace(lst_cipher[1], lst_cipher[2]);
  evaluator.sub_inplace(lst_cipher[0], lst_cipher[1]);
  evaluator.multiply_plain_inplace(lst_cipher[0],
                                   Plaintext(uint64_to_hex_string(s)));
  evaluator.add_plain_inplace(lst_cipher[0],
                              Plaintext(uint64_to_hex_string(s * r)));

  // send the bloom filter and hash key
  bytes = sizeof(uint64_t) + bf.compute_serialization_size();
  bytes_to_send(sockfd_client, bytes);
  uint8_t *bf_buf = (uint8_t *)malloc(bytes);
  *(uint64_t *)bf_buf = w;
  bf.serialize(bf_buf + sizeof(uint64_t));
  bytes = send(sockfd_client, bf_buf, bytes, 0);
  cout << "Send the BF to the client, bytes sent : " << bytes << endl;
  free(bf_buf);

  // send the encrypted blind distance
  stringstream stream_cipher;
  lst_cipher[0].save(stream_cipher);
  bytes_to_send(sockfd_client, stream_cipher.str().length());
  bytes = send(sockfd_client, stream_cipher.str().c_str(),
               stream_cipher.str().length(), 0);
  cout << "Send the encrypted blind distance to the client, bytes sent : "
       << bytes << endl;
  auto end = chrono::high_resolution_clock::now();
  auto elapsed = chrono::duration_cast<chrono::nanoseconds>(end - t1);

  printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
  close(sockfd_client);
  return 0;
  // }
}