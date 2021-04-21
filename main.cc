#include "mitm.h"
#include "replay.h"
#include "integrity.h"
#include "tinyTLS.h"
#include "tinyTLSClient.h"
#include "tinyTLSServer.h"
#include <bits/stdint-uintn.h>
#include <cstring>
#include <memory>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

int test() {
  int sum = 0;
  printf("--------------------------------Integrity--------------------------------\n");

  if(check_integrity() == -1){
    sum += 1;
    printf("PASS!\n");
  }

  printf(
      "--------------------------------MITM--------------------------------\n");
  if (mitm() == 0) {
    sum += 1;
    printf("MITM PASS!\n");
  }

  printf("--------------------------------REPLAY-------------------------------"
         "-\n");
  if (replay() == -1) {
    sum += 2;
    printf("REPLAY PASS!\n");
  }
  return sum;
}

int main() {
  printf("%d's score:%d\n", STUDENT_ID, test());
  return 0;
}
