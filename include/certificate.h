#pragma once

#include <openssl/sha.h>

class Certificate {
public:
  char CN[32];
  uint64_t expire_date;
  char *serverPubkeyPEM;
  char *signingkeyPEM;
  uint8_t hash[SHA256_DIGEST_LENGTH];
  uint8_t *signedHash;
  Certificate(const char *name);
  ~Certificate();
  int checkValid(const char *domain);
};