#include "tinyTLSServer.h"
#include "tinyTLS.h"

#include <bits/stdint-uintn.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <string.h>
#include <string>

TLSServer::TLSServer(const char *serverName) {
  rootCA = gernerateRSA();
  serverkey = gernerateRSA();
  int len = strlen(serverName);
  memcpy(CN, serverName, len > 32 ? 32 : len);
  CN[len] = 0;
  cert = generateCert(serverkey, rootCA);
}

TLSServer::TLSServer(const char *serverName, RSA *_serverkey, RSA *_rootCA) {
  rootCA = _rootCA;
  serverkey = _serverkey;
  cert = generateCert(serverkey, rootCA);
  int len = strlen(serverName);
  memcpy(CN, serverName, len > 32 ? 32 : len);
}

struct server_hello *TLSServer::send_server_hello() {
  auto hello = (struct server_hello *)malloc(sizeof(struct server_hello));
  hello->magic = MAGIC_SERVER_HELLO;
  hello->cert = cert;
  return hello;
}

struct server_hello *TLSServer::send_server_hello(int n) {
  auto hello = (struct server_hello *)malloc(sizeof(struct server_hello));
  hello->magic = MAGIC_SERVER_HELLO;
  if (n == 0)
    hello->cert = nullptr;
  else
    hello->cert = generateCert(serverkey, rootCA);
  return hello;
}

struct server_key_exchange *
TLSServer::send_server_key_exchange(struct client_key_exchange *param) {
  //printf("start send serverkey\n");
  if (param->errorno != 0) {
    printf("%s Server: Client abort due to worng certificate: %d\n", CN,
           param->errorno);
    return nullptr;
  }

  //printf("normal errorno\n");
  auto PMS = (uint8_t *)malloc(48);
  //printf("RSA Problem?\n");
  //RSA_private_decrypt(RSA_size(serverkey), param->encrypted_PMS, serverkey,RSA_PKCS1_OAEP_PADDING);
  //printf("RSA Problem?\n");

  SHA256_CTX c;
  SHA256_Init(&c);
  SHA256_Update(&c, PMS, 48);
  SHA256_Final(sessionKey, &c);

  printf("%s Server:handshake Done! sessionKey:", CN);
  print_hex(sessionKey, SHA256_DIGEST_LENGTH);
  auto ret =
      (struct server_key_exchange *)malloc(sizeof(struct server_key_exchange));
  ret->magic = MAGIC_SERVER_KEY_EXCHANGE;
  free(PMS);
  return ret;
}

void *TLSServer::handshake(void *param) {
  if (((uint64_t *)param)[0] == MAGIC_CLIENT_HELLO) {
    return (void *)send_server_hello();
  } else if (((uint64_t *)param)[0] == MAGIC_CLIENT_KEY_EXCHANGE) {
    return (void *)send_server_key_exchange(
        (struct client_key_exchange *)param);
  } else {
    return nullptr;
  }
}

Certificate *TLSServer::generateCert(RSA *_serverkey, RSA *_rootCA) {
  uint8_t buffer[3][SHA256_DIGEST_LENGTH];
  Certificate *cert = new Certificate(CN);
  cert->expire_date = 1650294000; // 2022-04-19 00:00:00
  SHA256_CTX c;
  SHA256_Init(&c);
  SHA256_Update(&c, cert->CN, strlen(cert->CN));
  SHA256_Final(buffer[0], &c);

  SHA256_Init(&c);
  SHA256_Update(&c, &cert->expire_date, sizeof(uint64_t));
  SHA256_Final(buffer[1], &c);

  BIO *bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPublicKey(bio, _serverkey);
  ssize_t keylen = BIO_pending(bio);
  cert->serverPubkeyPEM = (char *)malloc(keylen + 1);
  bzero(cert->serverPubkeyPEM, keylen + 1);
  BIO_read(bio, cert->serverPubkeyPEM, keylen);

  SHA256_Init(&c);
  SHA256_Update(&c, cert->serverPubkeyPEM, keylen);
  SHA256_Final(buffer[2], &c);

  BIO_free(bio);

  SHA256_Init(&c);
  SHA256_Update(&c, buffer[0], SHA256_DIGEST_LENGTH);
  SHA256_Update(&c, buffer[1], SHA256_DIGEST_LENGTH);
  SHA256_Update(&c, buffer[2], SHA256_DIGEST_LENGTH);
  SHA256_Final(cert->hash, &c);

  bio = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPublicKey(bio, _rootCA);
  keylen = BIO_pending(bio);
  cert->signingkeyPEM = (char *)malloc(keylen + 1);
  bzero(cert->signingkeyPEM, keylen + 1);
  BIO_read(bio, cert->signingkeyPEM, keylen);
  BIO_free(bio);
  cert->signedHash = (uint8_t *)malloc(RSA_size(_rootCA));
  int err = RSA_private_encrypt(SHA256_DIGEST_LENGTH, cert->hash,
                                cert->signedHash, _rootCA, RSA_PKCS1_PADDING);
  if (err == -1) {
    err = ERR_get_error();
    char buf[4096] = {0};
    ERR_error_string(err, buf);
    printf("error:%s\n", buf);
    return nullptr;
  }
  return cert;
}

RSA *TLSServer::CAkeyLeak() { return rootCA; }
