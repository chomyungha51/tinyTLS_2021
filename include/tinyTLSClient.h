#pragma once
#include "tinyTLS.h"
#include "tinyTLSServer.h"
#include <cstdio>
#include <openssl/rsa.h>
#include <openssl/sha.h>

class TLSClient : public TLS {
private:
  unsigned int studentID;

public:
  struct client_hello *generateClientHello();
  struct client_key_exchange *generateClientKeyExchange(Certificate *cert, const char* servername);
  TLSClient() {}
  TLSClient(unsigned int _studentID);
  int handshake(TLSServer *t, const char* servername);
};
