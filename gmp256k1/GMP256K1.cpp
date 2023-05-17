
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "GMP256K1.h"
#include "Point.h"
#include "../util.h"
#include "../hashing.h"

Secp256K1::Secp256K1() {
}

void Secp256K1::Init() {
	// Prime for the finite field
	P.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");

	// Set up field
	Int::SetupField(&P);

	// Generator point and order
	G.x.SetBase16("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
	G.y.SetBase16("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
	G.z.SetInt32(1);
	order.SetBase16("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

	Int::InitK1(&order);

	// Compute Generator table
	Point N(G);
	for(int i = 0; i < 32; i++) {
		GTable[i * 256] = N;
		N = DoubleDirect(N);
		for (int j = 1; j < 255; j++) {
			GTable[i * 256 + j] = N;
			N = AddDirect(N, GTable[i * 256]);
		}
		GTable[i * 256 + 255] = N; // Dummy point for check function
	}

}

Secp256K1::~Secp256K1() {
}

Point Secp256K1::Negation(Point &p) {
	Point Q;
	//Q.Clear();
	Q.x.Set(&p.x);
	Q.y.Set(&this->P);
	Q.y.Sub(&p.y);
	Q.z.SetInt32(1);
	return Q;
}

Point Secp256K1::DoubleDirect(Point &p) {
	Int _s;
	Int _p;
	Int a;
	Point r;
	r.z.SetInt32(1);
	_s.ModMulK1(&p.x,&p.x);
	_p.ModAdd(&_s,&_s);
	_p.ModAdd(&_s);

	a.ModAdd(&p.y,&p.y);
	a.ModInv();
	_s.ModMulK1(&_p,&a);     // s = (3*pow2(p.x))*inverse(2*p.y);

	_p.ModMulK1(&_s,&_s);
	a.ModAdd(&p.x,&p.x);
	a.ModNeg();
	r.x.ModAdd(&a,&_p);    // rx = pow2(s) + neg(2*p.x);

	a.ModSub(&r.x,&p.x);

	_p.ModMulK1(&a,&_s);
	r.y.ModAdd(&_p,&p.y);
	r.y.ModNeg();           // ry = neg(p.y + s*(ret.x+neg(p.x)));
	return r;
}

Int Secp256K1::GetY(Int x,bool isEven) {
	Int y;
	mpz_t _s,_p,y2;
	mpz_inits(_s,_p,y2,NULL);
	mpz_pow_ui(_s,x.num,3);
	mpz_add_ui(y2,_s,7);
	mpz_mod(y2,y2,P.num);
	mpz_add_ui(_s,P.num,1);
	mpz_fdiv_q_ui(_p,_s,4);
	mpz_powm(y.num,y2,_p,P.num);
	mpz_sub(_s,P.num,y.num);
	if(mpz_tstbit(y.num, 0) == 1 && isEven){
		mpz_set(y.num,_s);
	}else if (mpz_tstbit(y.num, 0) == 0 && !isEven)	{
		mpz_set(y.num,_s);
	}
	mpz_clears(_s,_p,y2,NULL);
	return y;
}

Point Secp256K1::ComputePublicKey(Int *privKey)	{
	//char *hextemp;
	uint8_t buffer[32];
	int i = 0;
	uint8_t b;
	Point Q;

	Q.Clear();
	privKey->Get32Bytes(buffer);
	for (i = 0; i < 32; i++) {
		b = buffer[i];
		if(b)
		  break;
	}
	if(i == 32)
		return Q;
	Q = GTable[256 * (31 - i) + (b-1)];
	i++;
	for(; i < 32; i++) {
		b = buffer[i];
		if(b)
			Q = Add2(Q, GTable[256 * (31 - i) + (b-1)]);
	}
	Q.Reduce();
	return Q;
}

Point Secp256K1::NextKey(Point &key) {
  // Input key must be reduced and different from G
  // in order to use AddDirect
  return AddDirect(key,G);
}

bool Secp256K1::EC(Point &p) {
	Int _s;
	Int _p;
	_s.ModSquareK1(&p.x);
	_p.ModMulK1(&_s,&p.x);
	_p.ModAdd(7);
	_s.ModMulK1(&p.y,&p.y);
	_s.ModSub(&_p);
	return _s.IsZero(); // ( ((pow2(y) - (pow3(x) + 7)) % P) == 0 );
}


bool Secp256K1::ParsePublicKeyHex(char *str,Point &ret,bool &isCompressed) {
	char tempbuffer[65];
	int len = strlen(str);
	ret.Clear();
	if (len < 2) {
		printf("ParsePublicKeyHex: Error invalid public key specified (66 or 130 character length)\n");
		return false;
	}
	uint8_t type = GetByte(str, 0);
	switch (type) {
		case 0x02:
			if (len != 66) {
				printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
				return false;
			}
			ret.x.SetBase16(str+2);
			ret.y = GetY(ret.x, true);
			isCompressed = true;
		break;

		case 0x03:
			if (len != 66) {
				printf("ParsePublicKeyHex: Error invalid public key specified (66 character length)\n");
				return false;
			}
			ret.x.SetBase16(str+2);
			ret.y = GetY(ret.x, false);
			isCompressed = true;
		break;
		case 0x04:
			if (len != 130) {
				printf("ParsePublicKeyHex: Error invalid public key specified (130 character length)\n");
				return false;
			}
			strncpy(tempbuffer,str+2,64);
			tempbuffer[64] = 0x00;
			ret.x.SetBase16(tempbuffer);
			ret.x.SetBase16(str+66);
			isCompressed = false;
		break;
		default:
			printf("ParsePublicKeyHex: Error invalid public key specified (Unexpected prefix (only 02,03 or 04 allowed)\n");
			return false;
	}

	ret.z.SetInt32(1);

	if (!EC(ret)) {
		printf("ParsePublicKeyHex: Error invalid public key specified (Not lie on elliptic curve)\n");
		return false;
	}
	return true;
}

char* Secp256K1::GetPublicKeyHex(bool compressed, Point &pubKey) {
  unsigned char publicKeyBytes[65];
  char *ret = NULL;
  if (!compressed) {
    //Uncompressed public key
    publicKeyBytes[0] = 0x4;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
    pubKey.y.Get32Bytes(publicKeyBytes + 33);
    ret = (char*) tohex((char*)publicKeyBytes,65);
  }
  else {
    // Compressed public key
    publicKeyBytes[0] = pubKey.y.IsEven() ? 0x02 : 0x03;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
    ret = (char*) tohex((char*)publicKeyBytes,33);
  }
  return ret;
}


/*
	The caller of this function must asuste that there are enough space in dst pointer
*/
void Secp256K1::GetPublicKeyHex(bool compressed, Point &pubKey,char *dst){
  unsigned char publicKeyBytes[65];
  if (!compressed) {
    //Uncompressed public key
    publicKeyBytes[0] = 0x4;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
    pubKey.y.Get32Bytes(publicKeyBytes + 33);
    tohex_dst((char*)publicKeyBytes,65,dst);
  }
  else {
    // Compressed public key
    publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes(publicKeyBytes + 1);
	tohex_dst((char*)publicKeyBytes,33,dst);
  }
}


char* Secp256K1::GetPublicKeyRaw(bool compressed, Point &pubKey) {
  char *ret = (char*) malloc(65);
  if(ret == NULL) {
    ::fprintf(stderr,"Can't alloc memory\n");
    exit(0);
  }
  if (!compressed) {
    //Uncompressed public key
    ret[0] = 0x04;
    pubKey.x.Get32Bytes((unsigned char*) (ret + 1));
    pubKey.y.Get32Bytes((unsigned char*) (ret + 33));
  }
  else {
    // Compressed public key
    ret[0] = pubKey.y.IsEven() ? 0x02 : 0x03;
    pubKey.x.Get32Bytes((unsigned char*) (ret + 1));
  }
  return ret;
}

/*
	The caller of this function must asuste that there are enough space in dst pointer
*/
void Secp256K1::GetPublicKeyRaw(bool compressed, Point &pubKey,char *dst) {
  if (!compressed) {
    //Uncompressed public key
    dst[0] = 0x4;
    pubKey.x.Get32Bytes((unsigned char*) (dst + 1));
    pubKey.y.Get32Bytes((unsigned char*) (dst + 33));
  }
  else {
    // Compressed public key
    dst[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
    pubKey.x.Get32Bytes((unsigned char*) (dst + 1));
  }
}

uint8_t Secp256K1::GetByte(char *str, int idx) {
  char tmp[3];
  int  val;
  tmp[0] = str[2 * idx];
  tmp[1] = str[2 * idx + 1];
  tmp[2] = 0;
  if (sscanf(tmp, "%X", &val) != 1) {
    printf("ParsePublicKeyHex: Error invalid public key specified (unexpected hexadecimal digit)\n");
    exit(-1);
  }
  return (uint8_t)val;
}







/*

*/


Point Secp256K1::AddDirect(Point &p1,Point &p2) {
  Int _s;
  Int _p;
  Int dy;
  Int dx;
  Point r;
  r.z.SetInt32(1);

  dy.ModSub(&p2.y,&p1.y);
  dx.ModSub(&p2.x,&p1.x);
  dx.ModInv();
  _s.ModMulK1(&dy,&dx);     // s = (p2.y-p1.y)*inverse(p2.x-p1.x);

  _p.ModSquareK1(&_s);       // _p = pow2(s)

  r.x.ModSub(&_p,&p1.x);
  r.x.ModSub(&p2.x);       // rx = pow2(s) - p1.x - p2.x;

  r.y.ModSub(&p2.x,&r.x);
  r.y.ModMulK1(&_s);
  r.y.ModSub(&p2.y);       // ry = - p2.y - s*(ret.x-p2.x);

  return r;
}

Point Secp256K1::Add2(Point &p1, Point &p2) {
  // P2.z = 1
  Int u;
  Int v;
  Int u1;
  Int v1;
  Int vs2;
  Int vs3;
  Int us2;
  Int a;
  Int us2w;
  Int vs2v2;
  Int vs3u2;
  Int _2vs2v2;
  Point r;
  u1.ModMulK1(&p2.y, &p1.z);
  v1.ModMulK1(&p2.x, &p1.z);
  u.ModSub(&u1, &p1.y);
  v.ModSub(&v1, &p1.x);
  us2.ModSquareK1(&u);
  vs2.ModSquareK1(&v);
  vs3.ModMulK1(&vs2, &v);
  us2w.ModMulK1(&us2, &p1.z);
  vs2v2.ModMulK1(&vs2, &p1.x);
  _2vs2v2.ModAdd(&vs2v2, &vs2v2);
  a.ModSub(&us2w, &vs3);
  a.ModSub(&_2vs2v2);

  r.x.ModMulK1(&v, &a);

  vs3u2.ModMulK1(&vs3, &p1.y);
  r.y.ModSub(&vs2v2, &a);
  r.y.ModMulK1(&r.y, &u);
  r.y.ModSub(&vs3u2);

  r.z.ModMulK1(&vs3, &p1.z);
  return r;
}



Point Secp256K1::Add(Point &p1,Point &p2) {
  Int u;
  Int v;
  Int u1;
  Int u2;
  Int v1;
  Int v2;
  Int vs2;
  Int vs3;
  Int us2;
  Int w;
  Int a;
  Int us2w;
  Int vs2v2;
  Int vs3u2;
  Int _2vs2v2;
  Int x3;
  Int vs3y1;
  Point r;


  /*
  U1 = Y2 * Z1
  U2 = Y1 * Z2
  V1 = X2 * Z1
  V2 = X1 * Z2
  if (V1 == V2)
    if (U1 != U2)
      return POINT_AT_INFINITY
    else
      return POINT_DOUBLE(X1, Y1, Z1)
  U = U1 - U2
  V = V1 - V2
  W = Z1 * Z2
  A = U ^ 2 * W - V ^ 3 - 2 * V ^ 2 * V2
  X3 = V * A
  Y3 = U * (V ^ 2 * V2 - A) - V ^ 3 * U2
  Z3 = V ^ 3 * W
  return (X3, Y3, Z3)
  */

  u1.ModMulK1(&p2.y,&p1.z);
  u2.ModMulK1(&p1.y,&p2.z);
  v1.ModMulK1(&p2.x,&p1.z);
  v2.ModMulK1(&p1.x,&p2.z);
  u.ModSub(&u1,&u2);
  v.ModSub(&v1,&v2);
  w.ModMulK1(&p1.z,&p2.z);
  us2.ModSquareK1(&u);
  vs2.ModSquareK1(&v);
  vs3.ModMulK1(&vs2,&v);
  us2w.ModMulK1(&us2,&w);
  vs2v2.ModMulK1(&vs2,&v2);
  _2vs2v2.ModAdd(&vs2v2,&vs2v2);
  a.ModSub(&us2w,&vs3);
  a.ModSub(&_2vs2v2);

  r.x.ModMulK1(&v,&a);

  vs3u2.ModMulK1(&vs3,&u2);
  r.y.ModSub(&vs2v2,&a);
  r.y.ModMulK1(&r.y,&u);
  r.y.ModSub(&vs3u2);

  r.z.ModMulK1(&vs3,&w);

  return r;
 
}

Point Secp256K1::Double(Point &p) {
	
  /*
  if (Y == 0)
    return POINT_AT_INFINITY
    W = a * Z ^ 2 + 3 * X ^ 2
    S = Y * Z
    B = X * Y*S
    H = W ^ 2 - 8 * B
    X' = 2*H*S
    Y' = W*(4*B - H) - 8*Y^2*S^2
    Z' = 8*S^3
    return (X', Y', Z')
  */

  Int z2;
  Int x2;
  Int _3x2;
  Int w;
  Int s;
  Int s2;
  Int b;
  Int _8b;
  Int _8y2s2;
  Int y2;
  Int h;
  Point r;
  z2.ModSquareK1(&p.z);
  z2.SetInt32(0); // a=0
  x2.ModSquareK1(&p.x);
  _3x2.ModAdd(&x2,&x2);
  _3x2.ModAdd(&x2);
  w.ModAdd(&z2,&_3x2);
  s.ModMulK1(&p.y,&p.z);
  b.ModMulK1(&p.y,&s);
  b.ModMulK1(&p.x);
  h.ModSquareK1(&w);
  _8b.ModAdd(&b,&b);
  _8b.ModDouble();
  _8b.ModDouble();
  h.ModSub(&_8b);
  r.x.ModMulK1(&h,&s);
  r.x.ModAdd(&r.x);
  s2.ModSquareK1(&s);
  y2.ModSquareK1(&p.y);
  _8y2s2.ModMulK1(&y2,&s2);
  _8y2s2.ModDouble();
  _8y2s2.ModDouble();
  _8y2s2.ModDouble();
  r.y.ModAdd(&b,&b);
  r.y.ModAdd(&r.y,&r.y);
  r.y.ModSub(&h);
  r.y.ModMulK1(&w);
  r.y.ModSub(&_8y2s2);
  r.z.ModMulK1(&s2,&s);
  r.z.ModDouble();
  r.z.ModDouble();
  r.z.ModDouble();
  return r;
}


Point Secp256K1::ScalarMultiplication(Point &P,Int *scalar)	{
	Point R,Q,T,Dummy;
	int  no_of_bits, loop;
	no_of_bits = scalar->GetBitLength();
	R.Clear();
	R.z.SetInt32(1);
	if(!scalar->IsZero())	{
		Q.Set(P);
		if(scalar->GetBit(0) == 1)	{
			R.Set(P);
		}
		for(loop = 1; loop < no_of_bits; loop++) {
			T = Double(Q);
			Q.Set(T);
			T.Set(R);
			if(scalar->GetBit(loop)){
				R = Add(T,Q);
			}
			else	{
				Dummy = Add(T,Q);
			}
		}
	}
	R.Reduce();
	return R;
}

void Secp256K1::GetHash160(int type, bool compressed, Point &pubKey, unsigned char *hash) {
	unsigned char shapk[64];
	switch (type) {
		case P2PKH:
		case BECH32:
			unsigned char publicKeyBytes[128];

			if (!compressed) {
				// Full public key
				publicKeyBytes[0] = 0x4;
				pubKey.x.Get32Bytes(publicKeyBytes + 1);
				pubKey.y.Get32Bytes(publicKeyBytes + 33);
				sha256(publicKeyBytes,65,shapk);
			} else {
				// Compressed public key
				publicKeyBytes[0] = pubKey.y.IsEven() ? 0x2 : 0x3;
				pubKey.x.Get32Bytes(publicKeyBytes + 1);
				sha256(publicKeyBytes,33,shapk);
			}
			rmd160(shapk,32,hash);
		
		break;
			case P2SH:
			// Redeem Script (1 to 1 P2SH)
			unsigned char script[64];
			script[0] = 0x00;  // OP_0
			script[1] = 0x14;  // PUSH 20 bytes
			GetHash160(P2PKH, compressed, pubKey, script + 2);
			sha256(script, 22, shapk);
			rmd160(shapk,32,hash);
		break;
	}
}

void Secp256K1::GetHash160(int type,bool compressed,
  Point &k0,Point &k1,Point &k2,Point &k3,
  uint8_t *h0,uint8_t *h1,uint8_t *h2,uint8_t *h3) {
	
	switch (type) {
		case P2PKH:
		case BECH32:
			unsigned char digests[4][65];

			if (!compressed) {
				// Full public key
				digests[0][0] = 0x4;
				digests[1][0] = 0x4;
				digests[2][0] = 0x4;
				digests[3][0] = 0x4;
				k0.x.Get32Bytes(digests[0] + 1);
				k0.y.Get32Bytes(digests[0] + 33);
				k1.x.Get32Bytes(digests[1] + 1);
				k1.y.Get32Bytes(digests[1] + 33);
				k2.x.Get32Bytes(digests[2] + 1);
				k2.y.Get32Bytes(digests[2] + 33);
				k3.x.Get32Bytes(digests[3] + 1);
				k3.y.Get32Bytes(digests[3] + 33);
				
				sha256_4(65, digests[0], digests[1],digests[2],digests[3],digests[0], digests[1],digests[2],digests[3]);
			} else {
				// Compressed public key
				digests[0][0] = (unsigned char) k0.y.IsEven() ? 0x2 : 0x3;
				digests[1][0] = (unsigned char) k1.y.IsEven() ? 0x2 : 0x3;
				digests[2][0] = (unsigned char) k2.y.IsEven() ? 0x2 : 0x3;
				digests[3][0] = (unsigned char) k3.y.IsEven() ? 0x2 : 0x3;
				k0.x.Get32Bytes(digests[0] + 1);
				k1.x.Get32Bytes(digests[1] + 1);
				k2.x.Get32Bytes(digests[2] + 1);
				k3.x.Get32Bytes(digests[3] + 1);
				sha256_4(33, digests[0], digests[1],digests[2],digests[3],digests[0], digests[1],digests[2],digests[3]);
			}
			rmd160_4(32, digests[0], digests[1],digests[2],digests[3],h0,h1,h2,h3);
		
		break;
			case P2SH:
			printf("Unsoported P2SH\n");
			exit(0);
			/*
			// Redeem Script (1 to 1 P2SH)
			unsigned char script[64];
			script[0] = 0x00;  // OP_0
			script[1] = 0x14;  // PUSH 20 bytes
			GetHash160(P2PKH, compressed, pubKey, script + 2);
			sha256(script, 22, shapk);
			rmd160(shapk,32,hash);
			*/
		break;
	}
}


void Secp256K1::GetHash160_fromX(int type,unsigned char prefix,
  Int *k0,Int *k1,Int *k2,Int *k3,
  uint8_t *h0,uint8_t *h1,uint8_t *h2,uint8_t *h3) {
	unsigned char digests[4][33];
	//int i;
	switch (type) {
		case P2PKH:
			
			k0->Get32Bytes((unsigned char*)(digests[0] + 1));
			k1->Get32Bytes((unsigned char*)(digests[1] + 1));
			k2->Get32Bytes((unsigned char*)(digests[2] + 1));
			k3->Get32Bytes((unsigned char*)(digests[3] + 1));
			digests[0][0] = prefix;
			digests[1][0] = prefix;
			digests[2][0] = prefix;
			digests[3][0] = prefix;
			
			sha256_4(33, digests[0], digests[1],digests[2],digests[3],digests[0], digests[1],digests[2],digests[3]);
			rmd160_4(32, digests[0], digests[1],digests[2],digests[3],h0,h1,h2,h3);

		break;

		case P2SH:
			fprintf(stderr,"[E] Fixme unsopported case");
			exit(0);
		break;
	}
}