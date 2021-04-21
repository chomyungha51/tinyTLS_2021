#pragma once

#include <bits/stdint-uintn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <string>

#include "certificate.h"

#define MAGIC_CLIENT_HELLO 0xffff0001
#define MAGIC_SERVER_HELLO 0xffff0002
#define MAGIC_CLIENT_KEY_EXCHANGE 0xffff0003
#define MAGIC_SERVER_KEY_EXCHANGE 0xffff0004

#define CERTERR_EXPIRE 1
#define CERTERR_SELFSIGN 2
#define CERTERR_WRONGCN 4

struct client_hello {
  uint64_t magic;
  unsigned int student_id;
};

struct server_hello {
  uint64_t magic;
  Certificate *cert;
};

struct client_key_exchange {
  uint64_t magic;
  uint8_t *encrypted_PMS;
  ssize_t pms_len;
  uint8_t errorno;
};

struct server_key_exchange {
  uint64_t magic;
};

class TLS {
protected:
  uint8_t sessionKey[SHA256_DIGEST_LENGTH];

public:
  RSA *gernerateRSA();
  int sendData(TLS* other, uint8_t *data, uint8_t *out, int *outl);
  int recvData(uint8_t *cipherText, uint8_t *out, ssize_t cryptolen,
               ssize_t taglen);

  // for student
  int sendData(TLS* other, uint8_t *data, uint8_t *out, int *outl, int replay);
  int recvData(uint8_t *cipherText, uint8_t *out, ssize_t cryptolen,
               ssize_t taglen, int replay);
  int addTag(uint8_t *msg, uint8_t *out);
  int checkTag(uint8_t *tag, ssize_t taglen);
};

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

void handleErrors();
void hex2byte(const char *str, uint8_t *bytes, unsigned int blen);
void print_hex(unsigned char *buffer, ssize_t len);
