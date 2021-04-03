/*
  gcc -o test test.c
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <cstring>
#include "SECP256k1.h"
#include "Point.h"
#include "Int.h"

#include "util.h"

Secp256K1 *secp;

int main()  {
  char dst[32];
  Int key;
  char *test;
  secp = new Secp256K1();
  key = new Int();
  secp->Init();
  Point punto;
  bool parity;
  if(secp->ParsePublicKeyHex((char*)"04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac",punto,parity))  {
    test = punto.x.GetBase16();
    printf("%s\n",test);
    free(test);
    test = punto.y.GetBase16();
    printf("%s\n",test);
    free(test);
  }
  else  {
    printf("Is not a valid point");
  }
  printf("%i\n",sizeof(Point));
  punto.x.Get32Bytes((unsigned char*)dst);
  test = tohex(dst,32);
  printf("%s\n",test);
  free(test);
}
