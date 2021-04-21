#include "tinyTLS.h"
#include "integrity.h"

int TLS::addTag(uint8_t *msg, uint8_t *out) {
  // Write your code here
  uint8_t *tag = (uint8_t *)malloc(64);
  encrypt(msg, sizeof(msg), sessionKey, NULL, tag);	////Again, encrypt encrypted data to make tag value
  *out = *msg + *tag;	//make msg+tag
  return sizeof(out);	//return the length of msg+tag
}

int TLS::checkTag(uint8_t *tag, ssize_t taglen) {
  // Write your code here - return 0 if tag is valid and return -1 if tag is
  // invalid
  // it is encrypted using sha256, enc(msg) and tag are same size(64 byte)
  auto extracted = (uint8_t *)malloc(64);
  auto checking = (uint8_t *)malloc(64);
  memcpy(extracted, tag, taglen);	//extract tag from received msg+tag
  memcpy(checking, tag-taglen, taglen);	//extract msg from received msg+tag
  if (extracted == checking) {	//tag valid
    return 0;
  }
  else {	//tag invalid
    return -1;
  }
  
}

int check_integrity(){
  TLSServer* server = new TLSServer("sslab.ctf.MIDTERM");
  TLSClient* client = new TLSClient(STUDENT_ID);

  if(client->handshake(server, "sslab.ctf.MIDTERM") == -1){
    return -2;
  }

  uint8_t buffer[2048]="CHECK MSG";
  uint8_t cipherText[2048] = {0};
  int cipherlen = 0;
  int taglen = client->sendData(server, buffer, cipherText, &cipherlen);
  cipherText[cipherlen - 0x4] += 1;
  bzero(buffer, 2048);
  return server->recvData(cipherText, buffer, cipherlen, taglen);
}
