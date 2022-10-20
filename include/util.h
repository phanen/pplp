
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// for non - interactive only
#ifdef dbg
#define dbg_pc(ct, log)                                                        \
  {                                                                            \
    Plaintext pdbg;                                                            \
    decryptor.decrypt((ct), (pdbg));                                           \
    cout << (log) << (pdbg).to_string() << endl;                               \
  }
#define dbg_pp(val, log)                                                       \
  { cout << (log) << (val) << end; }
#else
#define dbg_pc(ct, log) 1
#define dbg_pp(pt, log) 1
#endif

std::size_t get_bitlen(uint64_t x) {
  // 0 is 1 bit...
  std::size_t ret = 1;
  while (x >>= 1)
    ++ret;
  return ret;
}

// set the log level
constexpr bool flag_log = 1;
int dummy_printf(const char *__restrict __fmt, ...) { return 1; }
auto pplp_printf = flag_log ? std::printf : dummy_printf;

// - coordination of pre-send / pre-recv
// - handle the dynamic transmissions
constexpr int SIZE_BUFFER = 4096;
char buf[SIZE_BUFFER];

// pre-send the bytes length
void bytes_to_send(int sockfd, std::size_t bytes) {
  memset(buf, 0, SIZE_BUFFER);
  std::string str_bytes = std::to_string(bytes);
  send(sockfd, str_bytes.c_str(), SIZE_BUFFER, 0);
}

// pre-recv the bytes length
std::size_t bytes_to_receive(int sockfd) {
  memset(buf, 0, SIZE_BUFFER);
  recv(sockfd, buf, SIZE_BUFFER, 0);
  std::size_t bytes = std::stoull(buf);
  return bytes;
}

// send by stream (must tell the peer how many bytes)
ssize_t send_by_stream(int sockfd, std::stringstream &ss) {
  std::cout << "before tell" << std::endl;
  bytes_to_send(sockfd, ss.str().length());
  std::cout << "after tell" << std::endl;
  ssize_t bytes = send(sockfd, ss.str().c_str(), ss.str().length(), 0);
  return bytes;
}

// recv by stream
ssize_t recv_by_stream(int sockfd, std::stringstream &ss) {
  std::cout << "before tell" << std::endl;
  auto bytes = bytes_to_receive(sockfd);
  std::cout << "after tell" << std::endl;

  for (size_t remain_bytes = bytes; remain_bytes != 0;) {
    memset(buf, 0, sizeof(buf));
    auto cur_bytes =
        recv(sockfd, buf, std::min(size_t(remain_bytes), sizeof(buf)), 0);
    // if fail in half
    if (cur_bytes < 0)
      return cur_bytes; // instead... (bytes - remain_bytes)
    ss << std::string(buf, cur_bytes);
    remain_bytes -= cur_bytes;
  }
  return bytes;
}

int connect_to_server(std::string ip, uint16_t port) {
  // create a socket for server
  int sockfd_server = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd_server < 0) {
    perror("socket");
    return sockfd_server; // or -1
  }
  pplp_printf("client socket created..........\n");

  // connect to server
  struct sockaddr_in sockaddr_server;
  memset(&sockaddr_server, 0, sizeof(sockaddr_server));
  sockaddr_server.sin_family = AF_INET;
  sockaddr_server.sin_port = htons(port);
  sockaddr_server.sin_addr.s_addr = inet_addr(ip.c_str());

  int conn_result = connect(sockfd_server, (struct sockaddr *)&sockaddr_server,
                            sizeof(sockaddr_server));
  if (conn_result < 0) {
    perror("connect");
    close(sockfd_server);
    return -1;
  }

  return sockfd_server;
}

// specify server's listening sock(ip + port)
int connect_to_client(std::string ip, uint16_t port) {
  // crete a socket
  int sockfd_listening = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd_listening < 0) {
    perror("socket");
    return -1;
  }
  pplp_printf("socket created..................\n");

  // bind the ip address and port to a socket
  sockaddr_in myaddr;
  memset(&myaddr, 0, sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons(port);
  myaddr.sin_addr.s_addr = inet_addr(ip.c_str());
  int ret = bind(sockfd_listening, (struct sockaddr *)&myaddr, sizeof(myaddr));
  if (ret < 0) {
    perror("bind");
    return -1;
  }

  // socket is for listening
  ret = listen(sockfd_listening, 8);
  if (ret < 0) {
    perror("listen");
    return -1;
  }
  pplp_printf("listening...............\n");

  // wait for a connection
  sockaddr_in sockaddr_client;
  unsigned sz_client = sizeof(sockaddr_client);
  int sockfd_client = accept(sockfd_listening, (sockaddr *)&sockaddr_client,
                             (socklen_t *)&sz_client);
  if (sockfd_client < 0) {
    perror("accept");
    return -1;
  }

  // stop listening
  close(sockfd_listening);

  // print host:port of client
  char host[NI_MAXHOST];
  char serv[NI_MAXHOST];
  memset(host, 0, sizeof(host));
  memset(serv, 0, sizeof(serv));

  if (getnameinfo((sockaddr *)&sockaddr_client, sizeof(sockaddr_client), host,
                  NI_MAXHOST, serv, NI_MAXSERV, 0) == 0) {
    pplp_printf("Connected to client: %s:%s\n\n", host, serv);
  } else {
    inet_ntop(AF_INET, &sockaddr_client.sin_addr, host, NI_MAXHOST);
    pplp_printf("Connected to client: %s:%" PRIu16 "\n\n", host,
                ntohs(sockaddr_client.sin_port));
  }
  return sockfd_client;
}