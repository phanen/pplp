#include "benchmark.h"

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

  auto t_begin = chrono::high_resolution_clock::now();

  // radius
  string ip = cmd_parser.get<string>("host");
  uint16_t port = cmd_parser.get<uint16_t>("port");

  uint64_t xa = cmd_parser.get<uint64_t>("xa");
  uint64_t ya = cmd_parser.get<uint64_t>("ya");
  uint64_t radius = cmd_parser.get<uint64_t>("radius");

  size_t poly_modulus_degree_bits =
      cmd_parser.get<size_t>("poly_modulus_degree");
  size_t plain_modulus_bits = cmd_parser.get<size_t>("plain_modulus_bits");

  int sockfd_server = connect_to_server(ip, port);
  if (sockfd_server < 0)
    return sockfd_server; // force exit

  pplp_printf("Connected to the server,  test start...\n");

  // test leg
  radius = 16;
  for (size_t i = 0; i < 9; ++i) { // 2^4  2^12
    auto raw_data =
        test_client_leg(sockfd_server, radius, ip, port, xa, ya,
                        poly_modulus_degree_bits, plain_modulus_bits);
    parse2csv_client_leg("./client_legacy.csv", radius, i == 0, raw_data);
    radius <<= 1;
  }
  // // test opt
  // radius = 16;
  // for (size_t i = 0; i < 9; ++i) { // radius 8, 16, 32, ... , 4096 (4 ... 12)
  //   auto cur_vec =
  //       test_client_opt(sockfd_server, radius, ip, port, xa, ya,
  //                       poly_modulus_degree_bits, plain_modulus_bits);
  // }

  close(sockfd_server);
}

// legacy
static pair<TrafficLoad, DurationClient>
test_client_leg(int sockfd_server, uint64_t radius, string ip, uint16_t port,
                uint64_t xa, uint64_t ya, uint64_t poly_modulus_degree_bits,
                uint64_t plain_modulus_bits) {

  auto u = xa * xa + ya * ya;
  auto sq_raduis = radius * radius;

  pplp_printf("Proximity test start...\n");
  pplp_printf("Cerver's coordinates:\t(%" PRIu64 ", %" PRIu64 ")\n", xa, ya);
  pplp_printf("Radius:\t\t\t\t%" PRIu64 "\n", radius);

  uint64_t c_total = 0;

  auto t_init0 = chrono::high_resolution_clock::now();

  // set the parms
  EncryptionParameters parms(scheme_type::bfv);
  size_t poly_modulus_degree = 1ull << poly_modulus_degree_bits;
  size_t plain_modulus = 1ull << plain_modulus_bits;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(plain_modulus); // sq
  // set the context
  SEALContext context(parms);

  auto t_init1 = chrono::high_resolution_clock::now();

  if (flag_log)
    print_parameters(context);
  pplp_printf("Parameter validation: %s\n", context.parameter_error_message());

  auto t_kGen0 = chrono::high_resolution_clock::now();

  // generate sk and pk
  KeyGenerator keygen(context);
  SecretKey sk = keygen.secret_key();
  PublicKey pk;
  keygen.create_public_key(pk);

  auto t_kGen1 = chrono::high_resolution_clock::now();

  auto t_sendParms0 = chrono::high_resolution_clock::now();

  // send the parms to the server
  stringstream stream_parms;
  parms.save(stream_parms);
  ssize_t bytes = send(sockfd_server, stream_parms.str().c_str(),
                       stream_parms.str().length(), 0);

  auto t_sendParms1 = chrono::high_resolution_clock::now();

  auto c_sendParms = bytes;
  c_total += c_sendParms;

  auto t_sendPk0 = chrono::high_resolution_clock::now();

  // send the pk to the server
  stringstream stream_pk;
  pk.save(stream_pk);
  bytes_to_send(sockfd_server, stream_pk.str().length());
  bytes =
      send(sockfd_server, stream_pk.str().c_str(), stream_pk.str().length(), 0);
  pplp_printf("Send the public key to the server, bytes: %zu\n", bytes);

  auto t_sendPk1 = chrono::high_resolution_clock::now();

  auto c_sendPk = bytes;
  c_total += c_sendPk;

  auto t_sendCip0 = chrono::high_resolution_clock::now();

  auto t_enc0 = chrono::high_resolution_clock::now();

  // encrypt the data
  Ciphertext c1, c2, c3;
  Encryptor encryptor(context, pk);
  encryptor.encrypt(Plaintext(uint64_to_hex_string(u)), c1);
  encryptor.encrypt(Plaintext(uint64_to_hex_string(xa << 1)), c2);
  encryptor.encrypt(Plaintext(uint64_to_hex_string(ya << 1)), c3);

  auto t_enc1 = chrono::high_resolution_clock::now();

  uint64_t lst_c_sendCip[3];

  vector<Ciphertext> lst_cipher{c1, c2, c3};
  for (size_t id_cipher = 0; id_cipher < 3; id_cipher++) {
    stringstream stream_cipher;
    lst_cipher[id_cipher].save(stream_cipher);
    bytes = send_by_stream(sockfd_server, stream_cipher);
    pplp_printf("Send the ciphertext %zu, bytes: %zu\n", id_cipher,
                size_t(bytes));
    lst_c_sendCip[id_cipher] = bytes;
  }

  auto c_sendCips = lst_c_sendCip[0] + lst_c_sendCip[1] + lst_c_sendCip[2];
  c_total += c_sendCips;

  auto t_sendCip1 = chrono::high_resolution_clock::now();

  auto t_recvBF0 = chrono::high_resolution_clock::now();

  // receive the bloom filter from server
  bytes = bytes_to_receive(sockfd_server);
  //
  uint8_t *bf_buf = (uint8_t *)malloc(bytes);
  ssize_t remain_bytes = bytes;
  for (uint8_t *ptr = bf_buf; remain_bytes != 0;) {
    ssize_t cur_bytes = recv(sockfd_server, ptr, remain_bytes, 0);
    ptr += cur_bytes;
    remain_bytes -= cur_bytes;
  }
  uint64_t w = *(uint64_t *)bf_buf;
  bloom_filter bf(bf_buf + sizeof(uint64_t));
  pplp_printf("Recv the BF and hash key, bytes: %zu\n", size_t(bytes));
  //
  free(bf_buf);

  auto t_recvBF1 = chrono::high_resolution_clock::now();

  auto c_recvBF = bytes;
  c_total += c_recvBF;

  auto t_recvBD0 = chrono::high_resolution_clock::now();

  // receive the encrypted blind distance
  stringstream stream_cipher;
  bytes = recv_by_stream(sockfd_server, stream_cipher);
  Ciphertext cipher_blind_distance;
  cipher_blind_distance.load(context, stream_cipher);
  pplp_printf("Recv the encrypted blind distance, bytes: %zu\n", size_t(bytes));

  auto t_recvBD1 = chrono::high_resolution_clock::now();

  auto c_recvBD = bytes;
  c_total += c_recvBD;

  auto t_dec0 = chrono::high_resolution_clock::now();

  // decrypt the result to get the blind distance
  Decryptor decryptor(context, sk);
  Plaintext plain_blind_distance;
  decryptor.decrypt(cipher_blind_distance, plain_blind_distance);

  auto t_dec1 = chrono::high_resolution_clock::now();
  auto t_end = chrono::high_resolution_clock::now();

  uint64_t blind_distance =
      hex_string_to_uint(plain_blind_distance.to_string());
  pplp_printf("blind_distance: %" PRIu64 "\n", blind_distance);

  bool isNear = bf.contains((blind_distance << get_bitlen(w)) | w);

  pplp_printf(isNear ? "near\n" : "far\n");

  // parse the time points
  double d_init = get_diff(t_init1, t_init0);
  double d_kGen = get_diff(t_dec1, t_dec0);

  double d_sendPk = get_diff(t_sendPk1, t_sendPk0);
  double d_sendParms = get_diff(t_sendParms1, t_sendParms0);

  double d_recvBF = get_diff(t_recvBF1, t_recvBF0);

  double d_enc = get_diff(t_enc1, t_enc0);
  double d_sendCip = get_diff(t_sendCip1, t_sendCip0);

  double d_recvBD = get_diff(t_recvBD1, t_recvBD0);
  double d_dec = get_diff(t_dec1, t_dec0);

  double d_stage1 = d_init + d_kGen;
  double d_stage2 = 0.00;
  double d_stage3 = d_enc + d_dec;
  double d_total = get_diff(t_dec1, t_dec0);
  double d_totalCalc = d_stage1 + d_stage2 + d_stage3;
  double d_totalTraffic = 0.0;

  // parse the traffic loads
  auto c_totalsend = c_sendParms + c_sendPk + c_sendCips;
  auto c_totalrecv = c_total - c_totalsend;

  return {//
          TrafficLoad{
              .c_sendParms = (TrafficLoad::tl_t)c_sendParms, //
              .c_sendPk = (TrafficLoad::tl_t)c_sendPk,       //
              .c_sendCips = (TrafficLoad::tl_t)c_sendCips,   //
              .c_recvBF = (TrafficLoad::tl_t)c_recvBF,       //
              .c_recvBD = (TrafficLoad::tl_t)c_recvBD,       //
              .c_totalSend = (TrafficLoad::tl_t)c_totalsend, //
              .c_totalRecv = (TrafficLoad::tl_t)c_totalrecv,
              .c_total = (TrafficLoad::tl_t)c_total, //
          },
          DurationClient{
              .d_init = (DurationClient::dr_t)d_init,                 //
              .d_kGen = (DurationClient::dr_t)d_kGen,                 //
              .d_enc = (DurationClient::dr_t)d_enc,                   //
              .d_sendPk = (DurationClient::dr_t)d_sendPk,             //
              .d_sendParms = (DurationClient::dr_t)d_sendParms,       //
              .d_sendCip = (DurationClient::dr_t)d_sendCip,           //
              .d_recvBF = (DurationClient::dr_t)d_recvBF,             //
              .d_recvBD = (DurationClient::dr_t)d_recvBD,             //
              .d_dec = (DurationClient::dr_t)d_dec,                   //
              .d_stage1 = (DurationClient::dr_t)d_stage1,             //
              .d_stage2 = (DurationClient::dr_t)d_stage2,             //
              .d_stage3 = (DurationClient::dr_t)d_stage3,             //
              .d_total = (DurationClient::dr_t)d_total,               //
              .d_totalCalc = (DurationClient::dr_t)d_totalCalc,       //
              .d_totalTraffic = (DurationClient::dr_t)d_totalTraffic, //
          }};
}

// optimized
static std::pair<TrafficLoad, DurationClient>
test_client_opt(int sockfd_server, uint64_t radius, string ip, uint16_t port,
                uint64_t xa, uint64_t ya, uint64_t poly_modulus_degree_bits,
                uint64_t plain_modulus_bits) {

  auto u = xa * xa + ya * ya;

  uint64_t c_total = 0;

  auto t_init0 = chrono::high_resolution_clock::now();

  // set the parms
  EncryptionParameters parms(scheme_type::bfv);
  size_t poly_modulus_degree = 1ull << poly_modulus_degree_bits;
  size_t plain_modulus = 1ull << plain_modulus_bits;
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
  parms.set_plain_modulus(plain_modulus); // sq
  // set the context
  SEALContext context(parms);

  auto t_init1 = chrono::high_resolution_clock::now();

  if (flag_log)
    print_parameters(context);
  pplp_printf("Parameter validation: %s\n", context.parameter_error_message());

  auto t_kGen0 = chrono::high_resolution_clock::now();

  // generate sk and pk
  KeyGenerator keygen(context);
  SecretKey sk = keygen.secret_key();
  PublicKey pk;
  keygen.create_public_key(pk);

  auto t_kGen1 = chrono::high_resolution_clock::now();

  auto t_enc0 = chrono::high_resolution_clock::now();

  // encrypt the data
  Ciphertext c1, c2, c3;
  Encryptor encryptor(context, pk);
  encryptor.encrypt(Plaintext(uint64_to_hex_string(u)), c1);
  encryptor.encrypt(Plaintext(uint64_to_hex_string(xa << 1)), c2);
  encryptor.encrypt(Plaintext(uint64_to_hex_string(ya << 1)), c3);

  auto t_enc1 = chrono::high_resolution_clock::now();

  auto t_sendParms0 = chrono::high_resolution_clock::now();

  // send the parms to the server
  stringstream stream_parms;
  parms.save(stream_parms);
  ssize_t bytes = send(sockfd_server, stream_parms.str().c_str(),
                       stream_parms.str().length(), 0);

  auto t_sendParms1 = chrono::high_resolution_clock::now();

  auto c_sendParms = bytes;
  c_total += c_sendParms;

  auto t_sendPk0 = chrono::high_resolution_clock::now();

  // send the pk to the server
  stringstream stream_pk;
  pk.save(stream_pk);
  bytes_to_send(sockfd_server, stream_pk.str().length());
  bytes =
      send(sockfd_server, stream_pk.str().c_str(), stream_pk.str().length(), 0);
  pplp_printf("Send the public key to the server, bytes: %zu\n", bytes);

  auto t_sendPk1 = chrono::high_resolution_clock::now();

  auto c_sendPk = bytes;
  c_total += c_sendPk;

  auto t_sendCip0 = chrono::high_resolution_clock::now();

  uint64_t lst_c_sendCip[3];

  vector<Ciphertext> lst_cipher{c1, c2, c3};
  for (size_t id_cipher = 0; id_cipher < 3; id_cipher++) {
    stringstream stream_cipher;
    lst_cipher[id_cipher].save(stream_cipher);
    bytes = send_by_stream(sockfd_server, stream_cipher);
    pplp_printf("Send the ciphertext %zu, bytes: %zu\n", id_cipher,
                size_t(bytes));
    lst_c_sendCip[id_cipher] = bytes;
  }

  auto c_sendCips = lst_c_sendCip[0] + lst_c_sendCip[1] + lst_c_sendCip[2];
  c_total += c_sendCips;

  auto t_sendCip1 = chrono::high_resolution_clock::now();

  auto t_recvBF0 = chrono::high_resolution_clock::now();

  // receive the bloom filter from server
  bytes = bytes_to_receive(sockfd_server);
  //
  uint8_t *bf_buf = (uint8_t *)malloc(bytes);
  ssize_t remain_bytes = bytes;
  for (uint8_t *ptr = bf_buf; remain_bytes != 0;) {
    ssize_t cur_bytes = recv(sockfd_server, ptr, remain_bytes, 0);
    ptr += cur_bytes;
    remain_bytes -= cur_bytes;
  }
  uint64_t w = *(uint64_t *)bf_buf;
  bloom_filter bf(bf_buf + sizeof(uint64_t));
  pplp_printf("Recv the BF and hash key, bytes: %zu\n", size_t(bytes));
  //
  free(bf_buf);

  auto t_recvBF1 = chrono::high_resolution_clock::now();

  auto c_recvBF = bytes;
  c_total += c_recvBF;

  auto t_recvBD0 = chrono::high_resolution_clock::now();

  // receive the encrypted blind distance
  stringstream stream_cipher;
  bytes = recv_by_stream(sockfd_server, stream_cipher);
  Ciphertext cipher_blind_distance;
  cipher_blind_distance.load(context, stream_cipher);
  pplp_printf("Recv the encrypted blind distance, bytes: %zu\n", size_t(bytes));

  auto t_recvBD1 = chrono::high_resolution_clock::now();

  auto c_recvBD = bytes;
  c_total += c_recvBD;

  auto t_dec0 = chrono::high_resolution_clock::now();

  // decrypt the result to get the blind distance
  Decryptor decryptor(context, sk);
  Plaintext plain_blind_distance;
  decryptor.decrypt(cipher_blind_distance, plain_blind_distance);

  auto t_dec1 = chrono::high_resolution_clock::now();

  uint64_t blind_distance =
      hex_string_to_uint(plain_blind_distance.to_string());
  pplp_printf("blind_distance: %" PRIu64 "\n", blind_distance);

  bool isNear = bf.contains((blind_distance << get_bitlen(w)) | w);

  pplp_printf(isNear ? "near\n" : "far\n");

  // parse the time points
  time_vec ret;
  bytes_to_receive(sockfd_server);

  // get the diff of time
  auto get_diff = [](chrono::system_clock::time_point t1,
                     chrono::system_clock::time_point t0) {
    return chrono::duration_cast<chrono::nanoseconds>(t1 - t0).count();
  };

  double d_init = get_diff(t_init1, t_init0);
  double d_kGen = get_diff(t_dec1, t_dec0);
  double d_enc = get_diff(t_enc1, t_dec0);
  double d_sendPk = get_diff(t_sendPk1, t_sendPk0);
  double d_sendParms = get_diff(t_sendParms1, t_sendParms0);
  double d_sendCip = get_diff(t_sendCip1, t_sendCip0);
  double d_recvBF = get_diff(t_recvBF1, t_recvBF0);
  double d_recvBD = get_diff(t_recvBD1, t_recvBD0);
  double d_dec = get_diff(t_dec1, t_dec0);

  double d_stage1 = d_init + d_kGen + d_enc;
  double d_stage2 = 0.00;
  double d_stage3 = d_dec;

  // parse the traffic loads
  auto c_sendTotal = c_sendParms + c_sendPk + c_sendCips;
  auto c_recvTotal = c_total - c_sendTotal;

  return {
      //
      TrafficLoad{
          .c_sendParms = (TrafficLoad::tl_t)c_sendParms, //
          .c_sendPk = (TrafficLoad::tl_t)c_sendPk,       //
          .c_sendCips = (TrafficLoad::tl_t)c_sendCips,   //
          .c_recvBF = (TrafficLoad::tl_t)c_recvBF,       //
          .c_recvBD = (TrafficLoad::tl_t)c_recvBD,       //
          .c_totalSend = (TrafficLoad::tl_t)c_sendTotal, //
          .c_totalRecv = (TrafficLoad::tl_t)c_recvTotal,
          .c_total = (TrafficLoad::tl_t)c_total, //
      },
      DurationClient{
          .d_init = (DurationClient::dr_t)d_init,           //
          .d_kGen = (DurationClient::dr_t)d_kGen,           //
          .d_enc = (DurationClient::dr_t)d_enc,             //
          .d_sendPk = (DurationClient::dr_t)d_sendPk,       //
          .d_sendParms = (DurationClient::dr_t)d_sendParms, //
          .d_sendCip = (DurationClient::dr_t)d_sendCip,     //
          .d_recvBF = (DurationClient::dr_t)d_recvBF,       //
          .d_recvBD = (DurationClient::dr_t)d_recvBD,       //
          .d_dec = (DurationClient::dr_t)d_dec,             //
          .d_stage1 = (DurationClient::dr_t)d_stage1,       //
          .d_stage2 = (DurationClient::dr_t)d_stage2,       //
          .d_stage3 = (DurationClient::dr_t)d_stage3,       //
      }                                                     //
  };
}
