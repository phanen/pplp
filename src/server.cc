#include "seal/seal.h"

#include "bloomfilter.h"
#include "cmdline.h"
#include "examples.h" // print_parameter
#include "util.h"

#include <chrono>
#include <cinttypes>
#include <cstddef>
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
  cmd_parser.add<uint64_t>("xb", 'u', "coordinate1 of server", false, 123456888,
                           cmdline::range(0ul, 1ul << 27)); // 134217728
  cmd_parser.add<uint64_t>("yb", 'v', "coordinate2 of server", false, 132465777,
                           cmdline::range(0ul, 1ul << 27)); // 134217728

  cmd_parser.add<uint64_t>("radius", 'r', "radius/thershold", false, 128,
                           cmdline::range(1, 8192));

  cmd_parser.parse_check(argc, argv);

  string ip = cmd_parser.get<string>("host");
  uint16_t port = cmd_parser.get<uint16_t>("port");
  uint64_t xb = cmd_parser.get<uint64_t>("xb");
  uint64_t yb = cmd_parser.get<uint64_t>("yb");
  uint64_t radius = cmd_parser.get<uint64_t>("radius");

  uint64_t z = xb * xb + yb * yb;
  uint64_t sq_radius = radius * radius;

  int sockfd_client = connect_to_client(ip, port);
  if (sockfd_client < 0) // fail
    return -1;

  pplp_printf("Proximity test start...\n");
  pplp_printf("Server's coordinates:\t(%" PRIu64 ", %" PRIu64 ")\n", xb, yb);
  pplp_printf("Radius:\t\t\t\t%" PRIu64 "\n", radius);

  auto begin = chrono::high_resolution_clock::now();

  // Recv the parms
  auto bytes = recv(sockfd_client, buf, sizeof(buf), 0);
  pplp_printf("Recv the parms(context), bytes: %zu \n", size_t(bytes));

  // set the context
  EncryptionParameters parms;
  stringstream stream_parms(string((char *)buf, bytes));
  cout << "before load" << endl;
  parms.load(stream_parms);
  cout << "after load" << endl;

  SEALContext context(parms);
  if (flag_log)
    print_parameters(context);
  pplp_printf("Parameter validation: %s\n", context.parameter_error_message());

  // set the bloom filter
  bloom_parameters bf_parms;
  bf_parms.projected_element_count = sq_radius;
  bf_parms.false_positive_probability = 0.0001; // 1 in 10000
  bf_parms.random_seed = 0xA5A5A5A5;
  bf_parms.compute_optimal_parameters();
  bloom_filter bf(bf_parms);
  // generate the random number
  uint64_t r, s, w; // to fix
  random_bytes((byte *)&r, 4);
  random_bytes((byte *)&s, 4);
  random_bytes((byte *)&w, 2);
  int w_len = get_bitlen(w);
  for (uint64_t di = 0; di < sq_radius; ++di) {
    uint64_t bd = s * (di + r); // overflow ??
    bf.insert((bd << uint64_t(w_len)) | w);
  }

  // receive the encrypted data
  vector<Ciphertext> lst_cipher(3);
  // for each ciphertext
  for (size_t id_cipher = 0; id_cipher < 3; id_cipher++) {
    stringstream stream_cipher;
    bytes = recv_by_stream(sockfd_client, stream_cipher);
    lst_cipher[id_cipher].load(context, stream_cipher);
    pplp_printf("Recv the ciphertext %zu, bytes: %zu\n", id_cipher,
                size_t(bytes));
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

  // send the bloom filter and hash key (w || BF)
  bytes = sizeof(uint64_t) + bf.compute_serialization_size();
  bytes_to_send(sockfd_client, bytes);
  uint8_t *bf_buf = (uint8_t *)malloc(bytes);
  *(uint64_t *)bf_buf = w;
  bf.serialize(bf_buf + sizeof(uint64_t));
  bytes = send(sockfd_client, bf_buf, bytes, 0);
  pplp_printf("Send the BF and hash key, bytes: %zu\n", size_t(bytes));
  free(bf_buf);

  // send the encrypted blind distance
  stringstream stream_cipher;
  lst_cipher[0].save(stream_cipher);
  bytes_to_send(sockfd_client, stream_cipher.str().length());
  bytes = send(sockfd_client, stream_cipher.str().c_str(),
               stream_cipher.str().length(), 0);
  pplp_printf("Send the encrypted blind distance, bytes: %zu\n", size_t(bytes));

  auto end = chrono::high_resolution_clock::now();
  auto elapsed = chrono::duration_cast<chrono::nanoseconds>(end - begin);

  printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
  close(sockfd_client);
  return 0;
}