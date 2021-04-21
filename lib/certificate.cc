#include "certificate.h"
#include "tinyTLS.h"

#include <cstring>

int Certificate::checkValid(const char *domain) {
  int errorno = 0;
  if (expire_date < (unsigned)time(NULL)) {
    errorno |= CERTERR_EXPIRE;
  }
  if (!strcmp(signingkeyPEM, serverPubkeyPEM)) {
    errorno |= CERTERR_SELFSIGN;
  }
  if (strcmp(CN, domain)) {
    errorno |= CERTERR_WRONGCN;
  }
  return errorno;
}

Certificate::Certificate(const char *name) {
  if (strlen(name) > 32) {
    return;
  }
  memcpy(CN, name, strlen(name));
}
Certificate::~Certificate() {
  free(signedHash);
  free(serverPubkeyPEM);
  free(signingkeyPEM);
}