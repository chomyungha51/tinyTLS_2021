#include "replay.h"
#include "tinyTLS.h"
#include "tinyTLSClient.h"
#include "tinyTLSServer.h"
#include <cstring>
#include <iostream>

using namespace std;
static map<int, int>m; //front = reply, last = try

int replay() {
  uint8_t ctbuffer[2048] = {0};
  uint8_t ptbuffer[2048] = {0};
  TLSServer *bank = new TLSServer("sslab.ctf.MIDTERM");
  TLSClient *victim = new TLSClient(STUDENT_ID);
  if(victim->handshake(bank, "sslab.ctf.MIDTERM") == -1){
    std::cout << "Handshake not done!\n";
    return 0;
  };
  int cryptlen = 0;
  int taglen = victim->sendData(bank, (uint8_t *)"ALICE SEND 10000 TO EVE", ctbuffer,
                                &cryptlen);

  // This is relpay attack!
  bank->recvData(ctbuffer, ptbuffer, cryptlen, taglen);
  bank->recvData(ctbuffer, ptbuffer, cryptlen, taglen);
  bank->recvData(ctbuffer, ptbuffer, cryptlen, taglen);
  bank->recvData(ctbuffer, ptbuffer, cryptlen, taglen);
  bank->recvData(ctbuffer, ptbuffer, cryptlen, taglen);
  bank->recvData(ctbuffer, ptbuffer, cryptlen, taglen);
  bank->recvData(ctbuffer, ptbuffer, cryptlen, taglen);

  // Protect this protocol from replay attack!
  taglen =
      victim->sendData(bank, (uint8_t *)"ALICE SEND 10000 TO EVE", ctbuffer, &cryptlen, 0);
  bank->recvData(ctbuffer, ptbuffer, cryptlen, taglen, 0);
  return bank->recvData(ctbuffer, ptbuffer, cryptlen, taglen, 0);
}

//receiving duplicated data is a problem, so revise this fuction
int TLS::recvData(uint8_t *cipherText, uint8_t *out, ssize_t cryptolen,
                  ssize_t taglen, int replay) {
  // Write your code here
  int res;
  if (m.find(replay) == m.end()) {	//it is not a replay
    m[replay] = 0;
    decrypt(cipherText, cryptolen, sessionKey, NULL, out);
    int res = checkTag(cipherText + cryptolen, taglen);
    printf("RECV: %s\n", out);
  }
  else {
    res = -1;	//when you find same replay
  }
  
  return res;
}

//sendData is same
int TLS::sendData(TLS* other, uint8_t *data, uint8_t *out, int *outl, int replay) {
  // Write your code here
  int taglen = 0;
  uint8_t buffer[2048] = {0};
  *outl = encrypt(data, strlen((const char *)data), sessionKey, NULL, out);
  taglen = addTag(out+*outl, buffer);
  memcpy(out + *outl, buffer, taglen);
  bzero(buffer, 2048);
  //other->recvData(out, buffer, *outl, taglen);
  return taglen;
}
