#include "certificate.h"
#include "tinyTLS.h"
#include "tinyTLSClient.h"
#include "tinyTLSServer.h"

int mitm() {
  // Attacker make success that victim is access on their own server. But
  // unfortunantly, connection use TLS So victim abort access because of
  // authentication. Make sure that MITM(Man In The Middle) attack success!
  TLSServer *victimServer = new TLSServer("sslab.ctf.MIDTERM");
  TLSClient *victimClient = new TLSClient(STUDENT_ID);
  TLSServer *fakeServer = new TLSServer("FAKESERVER");
  TLSClient *fakeClient = new TLSClient(STUDENT_ID);

  RSA* leakKey = victimServer->CAkeyLeak();
  // Write your code on here
  // Hint) Authentication is based on certificate.
  
  delete fakeServer;	//delete original "FAKESERVER"'s TLSServer
  fakeServer = new TLSServer(victimServer->getCN());	//remake fakeServer's certificate with victimServer's servername "sslab.ctf.MIDTERM"	

  //now fakeServer has exactly same publicKey as victimServer's
  //Finally, it is valid when its CN and wanted domain name are tested
  
  int res = victimClient->handshake(fakeServer, "sslab.ctf.MIDTERM");
  res += fakeClient->handshake(victimServer, "sslab.ctf.MIDTERM");
  return res;
}
