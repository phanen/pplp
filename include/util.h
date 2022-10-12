
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <iostream>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
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

// radius
uint64_t th = 16;
uint64_t sq_threshold = th * th;
// run client and server in locally
uint16_t port = 51022;

constexpr bool flag_log = 1;
constexpr int SIZE_BUFFER = 4096;
constexpr const char *STOP_MSG = "STOP";
char buf[SIZE_BUFFER];

int dummy_printf(const char *__restrict __fmt, ...) { return 1; }
auto pplp_printf = flag_log ? std::printf : dummy_printf;

void bytes_to_send(int sockfd, std::size_t bytes) {
  std::string str_bytes = std::to_string(bytes);
  send(sockfd, str_bytes.c_str(), str_bytes.length() + 1, 0);
  recv(sockfd, buf, SIZE_BUFFER, 0);
}

std::size_t bytes_to_receive(int sockfd) {
  recv(sockfd, buf, SIZE_BUFFER, 0);
  std::size_t bytes = std::stoull(buf);
  send(sockfd, STOP_MSG, strlen(STOP_MSG), 0);
  return bytes;
}

int connect_to_server(std::string ip, uint16_t port) {
  // create a socket for server
  int sockfd_server = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd_server < 0) {
    perror("socket:");
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
    perror("connect:");
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
    perror("bind:");
    return -1;
  }

  // socket is for listening
  ret = listen(sockfd_listening, 8);
  if (ret < 0) {
    perror("listen:");
    return -1;
  }
  pplp_printf("listening...............\n");

  // wait for a connection
  sockaddr_in sockaddr_client;
  unsigned sz_client = sizeof(sockaddr_client);
  int sockfd_client = accept(sockfd_listening, (sockaddr *)&sockaddr_client,
                             (socklen_t *)&sz_client);
  if (sockfd_client < 0) {
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

  if (getnameinfo((sockaddr *)&sockaddr_client, sizeof(sockaddr_client), host,
                  NI_MAXHOST, serv, NI_MAXSERV, 0) == 0) {
    pplp_printf("Connected to client: %s:%s\n", host, serv);
  } else {
    inet_ntop(AF_INET, &sockaddr_client.sin_addr, host, NI_MAXHOST);
    pplp_printf("Connected to client: %s:%" PRIu16 "\n", host,
                ntohs(sockaddr_client.sin_port));
  }
  return sockfd_client;
}