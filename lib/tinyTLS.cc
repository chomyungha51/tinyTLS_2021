#include "tinyTLS.h"
#include <bits/stdint-uintn.h>
#include <cstdio>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/sha.h>
#include <strings.h>

int TLS::recvData(uint8_t *cipherText, uint8_t *out, ssize_t cryptolen,
                  ssize_t taglen) {
  decrypt(cipherText, cryptolen, sessionKey, NULL, out);
  int res = checkTag(cipherText + cryptolen, taglen);
  printf("RECV: %s\n", out);
  return res;
}

int TLS::sendData(TLS* other, uint8_t *data, uint8_t *out, int *outl) {
  int taglen = 0;
  uint8_t buffer[2048] = {0};
  *outl = encrypt(data, strlen((const char *)data), sessionKey, NULL, out);
  taglen = addTag(out, buffer);
  memcpy(out + *outl, buffer, taglen);
  bzero(buffer, 2048);
  other->recvData(out, buffer, *outl, taglen);
  return taglen;
}


RSA *TLS::gernerateRSA() {
  BIGNUM *e = BN_new();
  BN_set_word(e, 17);
  RSA *rsa = RSA_new();
  RSA_generate_key_ex(rsa, 1024, e, NULL);
  BN_free(e);
  return rsa;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();

  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    handleErrors();
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

void handleErrors() {
  int err = ERR_get_error();
  char buffer[2048] = {0};
  ERR_error_string(err, buffer);
  printf("ERROR:%s\n", buffer);
}

void hex2byte(const char *str, uint8_t *bytes, unsigned int blen) {
  uint8_t pos;
  uint8_t idx0;
  uint8_t idx1;

  // mapping of ASCII characters to hex values
  const uint8_t hashmap[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //  !"#$%&'
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ()*+,-./
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
      0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
      0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
      0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // pqrstuvw
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // xyz{|}~.
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ........
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // ........
  };

  bzero(bytes, blen);
  for (pos = 0; ((pos < (blen * 2)) && (pos < strlen(str))); pos += 2) {
    idx0 = (uint8_t)str[pos + 0];
    idx1 = (uint8_t)str[pos + 1];
    bytes[pos / 2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
  };
}

void print_hex(unsigned char *buffer, ssize_t len) {
  int i = 0;
  char outputBuffer[len * 2 + 1];
  for (i = 0; i < len; i++) {
    sprintf(outputBuffer + (i * 2), "%02x", buffer[i]);
  }
  outputBuffer[len * 2] = 0;
  printf("%s\n", outputBuffer);
}