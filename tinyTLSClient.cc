#include "tinyTLS.h"
#include "tinyTLSClient.h"
#include "tinyTLSServer.h"

#include <bits/stdint-uintn.h>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <string>

TLSClient::TLSClient(unsigned int _studentID) { studentID = _studentID; }


int TLSClient::handshake(TLSServer *server, const char* serverName) {

  int ret = -1;
  struct client_hello *hello = generateClientHello();
  if(hello == nullptr){
    printf("Client: You MUST implent generateClientHello() Function!\n");
    return -1;
  }

  auto serverHello = (struct server_hello *)server->handshake(hello);

  auto keyExchange = generateClientKeyExchange(serverHello->cert, serverName);
  if(keyExchange == nullptr){
    printf("Client: You MUST implent generateClientKeyExchange() Function!\n");
    return -1;
  }

  auto serverKeyExchange =
      (struct server_key_exchange *)server->handshake(keyExchange);

  if (serverKeyExchange == nullptr) {
    printf("Client: Handshake abort\n");
  } else {
    printf("Client:Handshake done! sessionkey:");
    print_hex(sessionKey, SHA256_DIGEST_LENGTH);
    free(serverKeyExchange);
    ret = 0;
  }
  delete serverHello->cert;
  free(hello);
  free(serverHello);
  free(keyExchange->encrypted_PMS);
  free(keyExchange);
  return ret;
}

struct client_hello *TLSClient::generateClientHello() {
  
  struct client_hello *clientHello = new client_hello;	//allocate memory
  // -------Write your code on here--------
  clientHello -> magic = MAGIC_CLIENT_HELLO;	//set client magic value
  printf("open generate client hello\n");	//set client id
  clientHello -> student_id = STUDENT_ID;
  // --------------------------------------

  return clientHello;
}

struct client_key_exchange *
TLSClient::generateClientKeyExchange(Certificate *cert, const char* servername) {
  struct client_key_exchange *clientKeyExchange = new client_key_exchange;	//allocate memory

  // -------Write your code on here--------
  /*
  1) Check Certificate's valid.
  2) generate Pre Master Secret
  3) encrypt Pre Master Secret by key on certificate
  4) generate sessionkey base on Pre Master Secret
  */

  int valid = cert->checkValid(servername);	//check received certificate

  if (valid == 0) {	//valid certificate
    
    clientKeyExchange -> errorno = (uint8_t)0;	//no error
    unsigned char PMS[48];	//48-byte PMS
    uint8_t *iv = nullptr;	//no use

    RAND_status();	//gernerate seed
    RAND_bytes(PMS,48);	//gernerate PMS



    //encrypt(PMS, sizeof(PMS),(unsigned char *)cert->serverPubkeyPEM,iv, clientKeyExchange->encrypted_PMS );	//encrypt PMS by key on certificate


    SHA256_CTX c;	//generate sessionkey base on PMS
    SHA256_Init(&c);
    SHA256_Update(&c, PMS, 48);
    print_hex(sessionKey, SHA256_DIGEST_LENGTH);
    clientKeyExchange -> magic = MAGIC_CLIENT_KEY_EXCHANGE;
  }
  else {
    clientKeyExchange -> errorno = 8;	//when there is an error
  }

  // --------------------------------------
  return clientKeyExchange;
}

