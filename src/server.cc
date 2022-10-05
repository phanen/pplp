#define _CRT_SECURE_NO_WARNINGS

#include <chrono>
#include <iostream>
#include <set>
#include <vector>

#include "seal/seal.h"
#include "util.h"
#include "bloomfilter.h"
#include "examples.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

constexpr int SIZE_BUFFER = 4096;
constexpr const char *STOP_MSG = "STOP";
char buf[SIZE_BUFFER];

using namespace std;
using namespace seal;

void bytes_to_send(int sockfd, std::size_t bytes)
{
  std::string dataToSend = std::to_string(bytes);
  send(sockfd, dataToSend.c_str(), dataToSend.length() + 1, 0);
  recv(sockfd, buf, SIZE_BUFFER, 0);
}

std::size_t bytes_to_receive(int sockfd)
{
  recv(sockfd, buf, SIZE_BUFFER, 0);
  std::size_t bytes = std::stoull(buf);
  send(sockfd, STOP_MSG, strlen(STOP_MSG), 0);
  return bytes;
}

int main()
{
  uint64_t xb = 300;
  uint64_t yb = 200;
  uint64_t z = xb * xb + yb * yb;

  cout << "Server's horizontal coordinates:\t" << xb << endl;
  cout << "Server's vertical coordinates:\t\t" << yb << endl;
  cout << "Radius(Threshold):\t\t\t" << th << endl;

  // crete a socket
  int sockfd_listening = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd_listening < 0)
  {
    perror("socket");
    return -1;
  }
  printf("socket created..................\n");

  // bind the ip address and port to a socket
  sockaddr_in myaddr;
  memset(&myaddr, 0, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons(local_test_port);
  myaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  int ret = bind(sockfd_listening, (struct sockaddr *)&myaddr, sizeof(myaddr));
  if (ret < 0)
  {
    perror("bind:");
    return -1;
  }

  // socket is for listening
  ret = listen(sockfd_listening, 8);
  if (ret < 0)
  {
    perror("listen:");
    return -1;
  }
  printf("listening...............\n");

  // wait for a connection
  sockaddr_in sockaddr_client;
  unsigned sz_client = sizeof(sockaddr_client);
  int sockfd_client = accept(sockfd_listening, (sockaddr *)&sockaddr_client, (socklen_t *)&sz_client);
  if (sockfd_client < 0)
  {
    perror("accept:");
    return -1;
  }

  // stop listening
  close(sockfd_listening);

  // print host:port of client
  char host[NI_MAXHOST];
  char serv[NI_MAXHOST];
  memset(host, 0, sizeof(host));
  memset(serv, 0, sizeof(serv));

  cout << "Conected to the client, proximity test start..." << ends;
  if (getnameinfo((sockaddr *)&sockaddr_client, sizeof(sockaddr_client), host, NI_MAXHOST, serv, NI_MAXSERV, 0) == 0)
  {
    std::cout << "client: " << host << ":" << serv << std::endl;
  }
  else
  {
    inet_ntop(AF_INET, &sockaddr_client.sin_addr, host, NI_MAXHOST);
    std::cout << host << ":" << ntohs(sockaddr_client.sin_port) << std::endl;
  }
  cout<<  "proximity test start...\n"<< endl;

  auto begin = std::chrono::high_resolution_clock::now();

  // set the parms
  EncryptionParameters parms(scheme_type::bfv);
  size_t poly_modulus_degree = 4096;     // 4096 * 8
  uint64_t plain_modulus_bit_count = 33; // 56
  uint64_t plain_modulus = 1ull << plain_modulus_bit_count;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(plain_modulus); // 0 -- 10, sq: 0 -- 100

  // send the parms(context) to the client
  std::stringstream stream_parms;
  parms.save(stream_parms);
  // cout << stream_parms.str() << endl;
  ssize_t bytes = send(sockfd_client, stream_parms.str().c_str(), stream_parms.str().length(), 0);
  std::cout << "Send parms(context) to the client, bytes: " << bytes << std::endl;

  // set the context
  SEALContext context(parms);
  print_parameters(context);
  cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

  // receive the pk from the client
  std::stringstream stream_pk;
  bytes = bytes_to_receive(sockfd_client);
  ssize_t bytes_tmp = bytes;
  while (bytes != 0)
  {
    memset(buf, 0, sizeof(buf));
    ssize_t cur_bytes = recv(sockfd_client, buf, sizeof(buf), 0);
    stream_pk << std::string((char *)buf, cur_bytes);
    bytes -= cur_bytes;
  };
  std::cout << "Receive the public key from the client, bytes: " << bytes_tmp << std::endl;
  PublicKey pk;
  pk.load(context, stream_pk);

  // set the bloom filter
  bloom_parameters bf_parms;
  bf_parms.projected_element_count = sq_threshold;
  bf_parms.false_positive_probability = 0.0001; // 1 in 10000
  bf_parms.random_seed = 0xA5A5A5A5;
  bf_parms.compute_optimal_parameters();
  bloom_filter bf(bf_parms);
  // generate the random number
  uint64_t r = 13, s = 17, w = 11;
  int w_len = get_bitlen(w);
  // insert key-hashed blind distance
  for (uint64_t di = 0; di < sq_threshold; ++di)
  {
    uint64_t bd = s * (di + r);
    bf.insert((bd << uint64_t(w_len)) | w);
    // cout << ((bd << uint64_t(w_len)) | w) << ' ';
  }
  // cout << endl;

  // reveive the encrypted data from the client
  std::vector<Ciphertext> lst_cipher;
  // for each ciphertext
  for (size_t id_cipher = 0; id_cipher < 3; id_cipher++)
  {
    bytes = bytes_to_receive(sockfd_client);
    Ciphertext cipher_tmp;
    std::stringstream stream_cipher;
    ssize_t bytes_tmp = bytes;
    while (bytes != 0)
    {
      memset(buf, 0, sizeof(buf));
      ssize_t cur_bytes = recv(sockfd_client, buf, sizeof(buf), 0);
      stream_cipher << std::string((char *)buf, cur_bytes);
      bytes -= cur_bytes;
    }
    cipher_tmp.load(context, stream_cipher);
    lst_cipher.push_back(cipher_tmp);
    std::cout << "Receive the ciphertext " << id_cipher + 1 << " from the client, bytes: " << bytes_tmp << std::endl;
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
  evaluator.multiply_plain_inplace(lst_cipher[0], Plaintext(uint64_to_hex_string(s)));
  evaluator.add_plain_inplace(lst_cipher[0], Plaintext(uint64_to_hex_string(s * r)));

  // send the bloom filter and hash key
  bytes = sizeof(uint64_t) + bf.compute_serialization_size();
  bytes_to_send(sockfd_client, bytes);
  uint8_t *bf_buf = (uint8_t *)malloc(bytes);
  *(uint64_t *)bf_buf = w;
  bf.serialize(bf_buf + sizeof(uint64_t));
  bytes = send(sockfd_client, bf_buf, bytes, 0);
  std::cout << "Send the BF to the client, bytes sent : " << bytes << std::endl;
  free(bf_buf);

  // send the encrypted blind distance
  std::stringstream stream_cipher;
  lst_cipher[0].save(stream_cipher);
  bytes_to_send(sockfd_client, stream_cipher.str().length());
  bytes = send(sockfd_client, stream_cipher.str().c_str(), stream_cipher.str().length(), 0);
  std::cout << "Send the encrypted blind distance to the client, bytes sent : " << bytes << std::endl;
  auto end = std::chrono::high_resolution_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

  printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
  close(sockfd_client);
  return 0;
}