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
  std::string str_bytes = std::to_string(bytes);
  send(sockfd, str_bytes.c_str(), str_bytes.length() + 1, 0);
  recv(sockfd, buf, SIZE_BUFFER, 0);
}

std::size_t bytes_to_receive(int sockfd)
{
  recv(sockfd, buf, SIZE_BUFFER, 0);
  std::size_t bytes = std::stoull(buf);
  send(sockfd, STOP_MSG, strlen(STOP_MSG), 0);
  return bytes;
}

// larger plain_modulus, smaller noise budget
// small plain_modulus restrict A
// large plain_modulus restrict B
// solution: large poly_modulus_degree, but slow

int main()
{
  uint64_t xa = 200;
  uint64_t ya = 201;
  uint64_t u = xa * xa + ya * ya;

  Plaintext p1(uint64_to_hex_string(u));
  Plaintext p2(uint64_to_hex_string(xa << 1));
  Plaintext p3(uint64_to_hex_string(ya << 1));

  std::string ip_addr = "127.0.0.1";
  uint16_t port = local_test_port;

  cout << "Client's horizontal coordinates:\t" << xa << endl;
  cout << "Client's vertical coordinates:\t\t" << ya << endl;
  cout << "Radius(Threshold):\t\t\t" << th << endl;

  // create a socket for server
  int sockfd_server = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd_server < 0)
  {
    perror("socket:");
    return -1;
  }
  printf("client socket created..........\n");

  // connect to server
  struct sockaddr_in sockaddr_server;
  memset(&sockaddr_server, 0, sizeof(sockaddr_server));
  sockaddr_server.sin_family = AF_INET;
  sockaddr_server.sin_port = htons(port);
  sockaddr_server.sin_addr.s_addr = inet_addr("127.0.0.1");
  int conn_result = connect(sockfd_server, (struct sockaddr *)&sockaddr_server, sizeof(sockaddr_server));
  if (conn_result < 0)
  {
    perror("connect:");
    close(sockfd_server);
    return -1;
  }

  cout << "Conected to the server,  proximity test start...\n"
       << endl;

  auto begin = std::chrono::high_resolution_clock::now();

  // receive the parms from the server
  ssize_t bytes = recv(sockfd_server, buf, sizeof(buf), 0);
  std::cout << "Receive parms from the server, bytes: " << bytes << std::endl;
  // set the parms and the context
  EncryptionParameters parms;
  std::stringstream stream_parms;
  stream_parms << std::string((char *)buf, bytes);
  parms.load(stream_parms);
  SEALContext context(parms);
  print_parameters(context);
  cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

  // generate sk and pk
  KeyGenerator keygen(context);
  SecretKey sk = keygen.secret_key();
  PublicKey pk;
  keygen.create_public_key(pk);

  // send the pk to the server
  std::stringstream stream_pk;
  pk.save(stream_pk);
  bytes_to_send(sockfd_server, stream_pk.str().length());
  bytes = send(sockfd_server, stream_pk.str().c_str(), stream_pk.str().length(), 0);
  std::cout << "Send the public key to the server, bytes: " << bytes << std::endl;

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
  bytes = send(sockfd_server, stream_cipher.str().c_str(), stream_cipher.str().length(), 0);
  std::cout << "Send the ciphertext 1 to the server, bytes: " << bytes << std::endl;

  stream_cipher.clear();
  stream_cipher.str(std::string());
  c2.save(stream_cipher);
  bytes_to_send(sockfd_server, stream_cipher.str().length());
  bytes = send(sockfd_server, stream_cipher.str().c_str(), stream_cipher.str().length(), 0);
  std::cout << "Send the ciphertext 2 to the server, bytes: " << bytes << std::endl;

  stream_cipher.clear();
  stream_cipher.str(std::string());
  c3.save(stream_cipher);
  bytes_to_send(sockfd_server, stream_cipher.str().length());
  bytes = send(sockfd_server, stream_cipher.str().c_str(), stream_cipher.str().length(), 0);
  std::cout << "Send the ciphertext 3 to the server, bytes: " << bytes << std::endl;

  // receive the bloom filter from server
  bytes = bytes_to_receive(sockfd_server);
  ssize_t bytes_tmp = bytes;
  uint8_t *bf_buf = (uint8_t *)malloc(bytes);
  uint8_t *p_bf_buf = bf_buf;
  while (bytes != 0)
  {
    ssize_t cur_bytes = recv(sockfd_server, p_bf_buf, bytes, 0);
    p_bf_buf += cur_bytes;
    bytes -= cur_bytes;
  }
  uint64_t w = *(uint64_t *)bf_buf;
  bloom_filter bf(bf_buf + sizeof(uint64_t));
  free(bf_buf);
  std::cout << "Receive the BF from the server, bytes: " << bytes_tmp << std::endl;

  // receive the encrypted data from the server
  Ciphertext cipher_blind_distance;
  stream_cipher.clear();
  stream_cipher.str(std::string());
  bytes = bytes_to_receive(sockfd_server);
  bytes_tmp = bytes;
  while (bytes != 0)
  {
    memset(buf, 0, sizeof(buf));
    ssize_t cur_bytes = recv(sockfd_server, buf, sizeof(buf), 0);
    stream_cipher << std::string(buf, cur_bytes);
    bytes -= cur_bytes;
  }
  cipher_blind_distance.load(context, stream_cipher);
  std::cout << "Receive the encrypted data from the server, bytes: " << bytes_tmp << std::endl;

  // decrypt the result to get the blind distance
  Decryptor decryptor(context, sk);
  Plaintext plain_blind_distance;
  decryptor.decrypt(cipher_blind_distance, plain_blind_distance);

  uint64_t blind_distance = hex_string_to_uint(plain_blind_distance.to_string());
  cout << "blind_distance: " << blind_distance << endl;
  bool isNear = bf.contains((blind_distance << get_bitlen(w)) | w);
  auto end = std::chrono::high_resolution_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

  std::cout << (isNear ? "near" : "far") << std::endl;
  std::printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
  std::cout << std::endl;
  close(sockfd_server);
  return 0;
}