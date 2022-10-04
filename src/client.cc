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

constexpr int SIZE_BUFFER = 8192;
constexpr const char *STOP_MSG = "STOP";

void bytes_to_send(int sockfd, std::size_t bytes)
{
  std::string dataToSend = std::to_string(bytes);
  uint8_t buf[SIZE_BUFFER];
  send(sockfd, dataToSend.c_str(), dataToSend.length(), 0);
  recv(sockfd, buf, SIZE_BUFFER, 0);
}

std::size_t bytes_to_receive(int sockfd)
{
  char buf[SIZE_BUFFER];
  recv(sockfd, buf, SIZE_BUFFER, 0);
  std::size_t bytes = std::stoull(buf);
  send(sockfd, STOP_MSG, (unsigned)strlen(STOP_MSG), 0);
  return bytes;
}

using namespace std;
using namespace seal;

// larger plain_modulus, smaller noise budget
// small plain_modulus restrict A
// large plain_modulus restrict B
// solution: large poly_modulus_degree, but slow

int main()
{
  uint64_t xa = 217;
  uint64_t ya = 201;
  uint64_t u = xa * xa + ya * ya;
  uint64_t th = 16;
  uint64_t sq_threshold = th * th;

  Plaintext p1(uint64_to_hex_string(u));
  Plaintext p2(uint64_to_hex_string(xa << 1));
  Plaintext p3(uint64_to_hex_string(ya << 1));

  std::string ip_addr = "127.0.0.1";
  int port = 31022;

  cout << "Client's horizontal coordinates:\t" << xa << endl;
  cout << "Client's vertical coordinates:\t" << ya << endl;
  cout << "Radius(Threshold):\t" << th << endl;

  // create a socket for server
  int sockfd_server = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd_server < 0)
  {
    perror("socket:");
    return -1;
  }
  printf("client socket create success........\n");

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

  char buf[SIZE_BUFFER];
  std::string userInput;
  auto begin = std::chrono::high_resolution_clock::now();

  // receive the parm from the server
  ssize_t bytes = recv(sockfd_server, buf, SIZE_BUFFER, 0);
  std::cout << "Receive context from the server, bytes: " << bytes << std::endl;
  EncryptionParameters parms;
  std::stringstream stream_parms;
  stream_parms << std::string((char *)buf, bytes);
  parms.load(stream_parms);

  // get the context
  SEALContext context(parms);
  print_parameters(context);
  cout << "Parameter validation (success): " << context.parameter_error_message() << endl;

  // keygen
  KeyGenerator keygen(context);
  stream_parms.seekg(0, stream_parms.beg);
  SecretKey sk = keygen.secret_key();
  PublicKey pk;
  keygen.create_public_key(pk);

  // send the pk to the server
  std::stringstream stream_pk;
  pk.save(stream_pk);
  bytes = send(sockfd_server, stream_parms.str().c_str(), stream_parms.str().length(), 0);
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
  recv(sockfd_server, buf, sizeof(buf), 0);
  std::cout << "Send the ciphertext 1 to the client, bytes: " << bytes << std::endl;

  stream_cipher.clear();
  stream_cipher.str(std::string());
  c2.save(stream_cipher);
  bytes_to_send(sockfd_server, stream_cipher.str().length());
  bytes = send(sockfd_server, stream_cipher.str().c_str(), stream_cipher.str().length(), 0);
  recv(sockfd_server, buf, sizeof(buf), 0);
  std::cout << "Send the ciphertext 2 to the client, bytes: " << bytes << std::endl;

  stream_cipher.clear();
  stream_cipher.str(std::string());
  c3.save(stream_cipher);
  bytes_to_send(sockfd_server, stream_cipher.str().length());
  bytes = send(sockfd_server, stream_cipher.str().c_str(), stream_cipher.str().length(), 0);
  recv(sockfd_server, buf, sizeof(buf), 0);
  std::cout << "Send the ciphertext 3 to the client, bytes: " << bytes << std::endl;

  // receive the bloom filter from server

  // receive m from the server

  // receive the encrypted data from
  Ciphertext cipher_blind_distance;
  stream_cipher.clear();
  stream_cipher.str(std::string());
  bytes = bytes_to_receive(sockfd_server);
  while (bytes != 0)
  {
    memset(buf, 0, sizeof(buf));
    ssize_t cur_bytes = recv(sockfd_server, buf, sizeof(buf), 0);
    stream_cipher << std::string(buf, cur_bytes);
    bytes -= cur_bytes;
  }
  cipher_blind_distance.load(context, stream_cipher);
  std::cout << "Receive the encrypted data from the server, bytes: " << bytes << std::endl;

  // decrypt the result to get the blind distance
  Decryptor decryptor(context, sk);
  Plaintext plain_blind_distance;
  decryptor.decrypt(cipher_blind_distance, plain_blind_distance);
  uint64_t blind_distance = hex_string_to_uint(plain_blind_distance.to_string());
  cout << "blind_distance: " << blind_distance << endl;

  bool isNear = bf.contains((blind_distance << uint64_t(w_len)) | w);
  auto end = std::chrono::high_resolution_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);

  std::cout << (isNear ? "near" : "far") << std::endl;
  std::printf("Time measured: %.3f seconds.\n", elapsed.count() * 1e-9);
  std::cout << std::endl;

  close(sockfd_server);
  return 0;
}