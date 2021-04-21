#pragma once
#include "tinyTLS.h"
#include <openssl/rsa.h>
#include <openssl/sha.h>
class TLSServer : public TLS {
private:
  RSA *rootCA;
  RSA *serverkey;
  Certificate *cert;
  char CN[32];
  struct server_hello *send_server_hello();
  struct server_hello *send_server_hello(int n);
  struct server_key_exchange *
  send_server_key_exchange(struct client_key_exchange *param);
  Certificate *generateCert(RSA *_serverkey, RSA *_rootCA);

public:
  void setCertificate(Certificate *_cert) { cert = _cert; }
  char* getCN(){return CN;}
  TLSServer(const char *serverName);
  TLSServer(const char *serverName, RSA *_serverkey, RSA *_rootCA);
  uint8_t *senddata(uint8_t *encrypted_data);
  void *handshake(void *param);
  RSA *CAkeyLeak();
  ~TLSServer() {
    RSA_free(rootCA);
    RSA_free(serverkey);
  }
};