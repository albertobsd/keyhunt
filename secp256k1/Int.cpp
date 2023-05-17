/*
 * This file is part of the BSGS distribution (https://github.com/JeanLucPons/BSGS).
 * Copyright (c) 2020 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "Int.h"
#include "IntGroup.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <emmintrin.h>

#define MAX(x,y) (((x)>(y))?(x):(y))
#define MIN(x,y) (((x)<(y))?(x):(y))

Int _ONE((uint64_t)1);


// ------------------------------------------------

Int::Int() {
  CLEAR();
}

Int::Int(Int *a) {
  if(a) Set(a);
  else CLEAR();
}

Int::Int(int32_t i32) {
  if (i32 < 0) {
	  CLEARFF();
  } else {
	  CLEAR();
  }
  bits[0] = i32;
}

Int::Int(int64_t i64) {

  if (i64 < 0) {
	  CLEARFF();
  } else {
	  CLEAR();
  }
  bits64[0] = i64;
}

Int::Int(uint64_t u64) {

  CLEAR();
  bits64[0] = u64;

}

// ------------------------------------------------

void Int::CLEAR() {
  memset(bits64,0, NB64BLOCK*8);
}

void Int::CLEARFF() {
  memset(bits64, 0xFF, NB64BLOCK * 8);
}

// ------------------------------------------------

void Int::Set(Int *a) {
  for (int i = 0; i<NB64BLOCK; i++)
  	bits64[i] = a->bits64[i];
}

// ------------------------------------------------

void Int::Add(Int *a) {

  unsigned char c = 0;
  c = _addcarry_u64(c, bits64[0], a->bits64[0], bits64 +0);
  c = _addcarry_u64(c, bits64[1], a->bits64[1], bits64 +1);
  c = _addcarry_u64(c, bits64[2], a->bits64[2], bits64 +2);
  c = _addcarry_u64(c, bits64[3], a->bits64[3], bits64 +3);
  c = _addcarry_u64(c, bits64[4], a->bits64[4], bits64 +4);
#if NB64BLOCK > 5
  c = _addcarry_u64(c, bits64[5], a->bits64[5], bits64 +5);
  c = _addcarry_u64(c, bits64[6], a->bits64[6], bits64 +6);
  c = _addcarry_u64(c, bits64[7], a->bits64[7], bits64 +7);
  c = _addcarry_u64(c, bits64[8], a->bits64[8], bits64 +8);
#endif

}

// ------------------------------------------------

void Int::Add(uint64_t a) {

	unsigned char c = 0;
	c = _addcarry_u64(c, bits64[0], a, bits64 + 0);
	c = _addcarry_u64(c, bits64[1], 0, bits64 + 1);
	c = _addcarry_u64(c, bits64[2], 0, bits64 + 2);
	c = _addcarry_u64(c, bits64[3], 0, bits64 + 3);
	c = _addcarry_u64(c, bits64[4], 0, bits64 + 4);
#if NB64BLOCK > 5
	c = _addcarry_u64(c, bits64[5], 0, bits64 + 5);
	c = _addcarry_u64(c, bits64[6], 0, bits64 + 6);
	c = _addcarry_u64(c, bits64[7], 0, bits64 + 7);
	c = _addcarry_u64(c, bits64[8], 0, bits64 + 8);
#endif
}

// ------------------------------------------------
void Int::AddOne() {

  unsigned char c = 0;
  c = _addcarry_u64(c, bits64[0],1, bits64 +0);
  c = _addcarry_u64(c, bits64[1],0, bits64 +1);
  c = _addcarry_u64(c, bits64[2],0, bits64 +2);
  c = _addcarry_u64(c, bits64[3],0, bits64 +3);
  c = _addcarry_u64(c, bits64[4],0, bits64 +4);
#if NB64BLOCK > 5
  c = _addcarry_u64(c, bits64[5],0, bits64 +5);
  c = _addcarry_u64(c, bits64[6],0, bits64 +6);
  c = _addcarry_u64(c, bits64[7],0, bits64 +7);
  c = _addcarry_u64(c, bits64[8],0, bits64 +8);
#endif

}

// ------------------------------------------------

void Int::Add(Int *a,Int *b) {

  unsigned char c = 0;
  c = _addcarry_u64(c, b->bits64[0], a->bits64[0], bits64 +0);
  c = _addcarry_u64(c, b->bits64[1], a->bits64[1], bits64 +1);
  c = _addcarry_u64(c, b->bits64[2], a->bits64[2], bits64 +2);
  c = _addcarry_u64(c, b->bits64[3], a->bits64[3], bits64 +3);
  c = _addcarry_u64(c, b->bits64[4], a->bits64[4], bits64 +4);
#if NB64BLOCK > 5
  c = _addcarry_u64(c, b->bits64[5], a->bits64[5], bits64 +5);
  c = _addcarry_u64(c, b->bits64[6], a->bits64[6], bits64 +6);
  c = _addcarry_u64(c, b->bits64[7], a->bits64[7], bits64 +7);
  c = _addcarry_u64(c, b->bits64[8], a->bits64[8], bits64 +8);
#endif

}

// ------------------------------------------------

bool Int::IsGreater(Int *a) {

  int i;

  for(i=NB64BLOCK-1;i>=0;) {
    if( a->bits64[i]!= bits64[i] )
		break;
    i--;
  }

  if(i>=0) {
    return bits64[i]>a->bits64[i];
  } else {
    return false;
  }

}

// ------------------------------------------------

bool Int::IsLower(Int *a) {

  int i;

  for (i = NB64BLOCK - 1; i >= 0;) {
    if (a->bits64[i] != bits64[i])
      break;
    i--;
  }

  if (i >= 0) {
    return bits64[i]<a->bits64[i];
  } else {
    return false;
  }

}

// ------------------------------------------------

bool Int::IsGreaterOrEqual(Int *a) {

  Int p;
  p.Sub(this,a);
  return p.IsPositive();

}

// ------------------------------------------------

bool Int::IsLowerOrEqual(Int *a) {

  int i = NB64BLOCK - 1;

  while (i >= 0) {
    if (a->bits64[i] != bits64[i])
      break;
    i--;
}

  if (i >= 0) {
    return bits64[i]<a->bits64[i];
  } else {
    return true;
  }

}

bool Int::IsEqual(Int *a) {

return

#if NB64BLOCK > 5
  (bits64[8] == a->bits64[8]) &&
  (bits64[7] == a->bits64[7]) &&
  (bits64[6] == a->bits64[6]) &&
  (bits64[5] == a->bits64[5]) &&
#endif
  (bits64[4] == a->bits64[4]) &&
  (bits64[3] == a->bits64[3]) &&
  (bits64[2] == a->bits64[2]) &&
  (bits64[1] == a->bits64[1]) &&
  (bits64[0] == a->bits64[0]);
}

bool Int::IsOne() {
  return IsEqual(&_ONE);
}

bool Int::IsZero() {
#if NB64BLOCK > 5
  return (bits64[8] | bits64[7] | bits64[6] | bits64[5] | bits64[4] | bits64[3] | bits64[2] | bits64[1] | bits64[0]) == 0;
#else
  return (bits64[4] | bits64[3] | bits64[2] | bits64[1] | bits64[0]) == 0;
#endif

}


// ------------------------------------------------

void Int::SetInt64(uint64_t value) {
  CLEAR();
  bits64[0]=value;
}

// ------------------------------------------------

void Int::SetInt32(uint32_t value) {
  CLEAR();
  bits[0]=value;
}

// ------------------------------------------------

uint32_t Int::GetInt32() {
  return bits[0];
}

uint64_t Int::GetInt64() {
  return bits64[0];
}


// ------------------------------------------------

unsigned char Int::GetByte(int n) {

  unsigned char *bbPtr = (unsigned char *)bits;
  return bbPtr[n];

}

void Int::Set32Bytes(unsigned char *bytes) {

  CLEAR();
  uint64_t *ptr = (uint64_t *)bytes;
  bits64[3] = _byteswap_uint64(ptr[0]);
  bits64[2] = _byteswap_uint64(ptr[1]);
  bits64[1] = _byteswap_uint64(ptr[2]);
  bits64[0] = _byteswap_uint64(ptr[3]);

}

void Int::Get32Bytes(unsigned char *buff) {

  uint64_t *ptr = (uint64_t *)buff;
  ptr[3] = _byteswap_uint64(bits64[0]);
  ptr[2] = _byteswap_uint64(bits64[1]);
  ptr[1] = _byteswap_uint64(bits64[2]);
  ptr[0] = _byteswap_uint64(bits64[3]);

}

// ------------------------------------------------

void Int::SetByte(int n,unsigned char byte) {

	unsigned char *bbPtr = (unsigned char *)bits;
	bbPtr[n] = byte;

}

// ------------------------------------------------

void Int::SetDWord(int n,uint32_t b) {
  bits[n] = b;
}

// ------------------------------------------------

void Int::SetQWord(int n, uint64_t b) {
	bits64[n] = b;
}

// ------------------------------------------------

void Int::Sub(Int *a) {

  unsigned char c = 0;
  c = _subborrow_u64(c, bits64[0], a->bits64[0], bits64 +0);
  c = _subborrow_u64(c, bits64[1], a->bits64[1], bits64 +1);
  c = _subborrow_u64(c, bits64[2], a->bits64[2], bits64 +2);
  c = _subborrow_u64(c, bits64[3], a->bits64[3], bits64 +3);
  c = _subborrow_u64(c, bits64[4], a->bits64[4], bits64 +4);
#if NB64BLOCK > 5
  c = _subborrow_u64(c, bits64[5], a->bits64[5], bits64 +5);
  c = _subborrow_u64(c, bits64[6], a->bits64[6], bits64 +6);
  c = _subborrow_u64(c, bits64[7], a->bits64[7], bits64 +7);
  c = _subborrow_u64(c, bits64[8], a->bits64[8], bits64 +8);
#endif

}

// ------------------------------------------------

void Int::Sub(Int *a,Int *b) {

  unsigned char c = 0;
  c = _subborrow_u64(c, a->bits64[0], b->bits64[0], bits64 + 0);
  c = _subborrow_u64(c, a->bits64[1], b->bits64[1], bits64 + 1);
  c = _subborrow_u64(c, a->bits64[2], b->bits64[2], bits64 + 2);
  c = _subborrow_u64(c, a->bits64[3], b->bits64[3], bits64 + 3);
  c = _subborrow_u64(c, a->bits64[4], b->bits64[4], bits64 + 4);
#if NB64BLOCK > 5
  c = _subborrow_u64(c, a->bits64[5], b->bits64[5], bits64 + 5);
  c = _subborrow_u64(c, a->bits64[6], b->bits64[6], bits64 + 6);
  c = _subborrow_u64(c, a->bits64[7], b->bits64[7], bits64 + 7);
  c = _subborrow_u64(c, a->bits64[8], b->bits64[8], bits64 + 8);
#endif

}

void Int::Sub(uint64_t a) {

  unsigned char c = 0;
  c = _subborrow_u64(c, bits64[0], a, bits64 + 0);
  c = _subborrow_u64(c, bits64[1], 0, bits64 + 1);
  c = _subborrow_u64(c, bits64[2], 0, bits64 + 2);
  c = _subborrow_u64(c, bits64[3], 0, bits64 + 3);
  c = _subborrow_u64(c, bits64[4], 0, bits64 + 4);
#if NB64BLOCK > 5
  c = _subborrow_u64(c, bits64[5], 0, bits64 + 5);
  c = _subborrow_u64(c, bits64[6], 0, bits64 + 6);
  c = _subborrow_u64(c, bits64[7], 0, bits64 + 7);
  c = _subborrow_u64(c, bits64[8], 0, bits64 + 8);
#endif

}

void Int::SubOne() {

  unsigned char c = 0;
  c = _subborrow_u64(c, bits64[0], 1, bits64 + 0);
  c = _subborrow_u64(c, bits64[1], 0, bits64 + 1);
  c = _subborrow_u64(c, bits64[2], 0, bits64 + 2);
  c = _subborrow_u64(c, bits64[3], 0, bits64 + 3);
  c = _subborrow_u64(c, bits64[4], 0, bits64 + 4);
#if NB64BLOCK > 5
  c = _subborrow_u64(c, bits64[5], 0, bits64 + 5);
  c = _subborrow_u64(c, bits64[6], 0, bits64 + 6);
  c = _subborrow_u64(c, bits64[7], 0, bits64 + 7);
  c = _subborrow_u64(c, bits64[8], 0, bits64 + 8);
#endif

}

// ------------------------------------------------

bool Int::IsPositive() {
  return (int64_t)(bits64[NB64BLOCK - 1])>=0;
}

// ------------------------------------------------

bool Int::IsNegative() {
  return (int64_t)(bits64[NB64BLOCK - 1])<0;
}

// ------------------------------------------------

bool Int::IsStrictPositive() {
  if( IsPositive() )
	  return !IsZero();
  else
	  return false;
}

// ------------------------------------------------

bool Int::IsEven() {
  return (bits[0] & 0x1) == 0;
}

// ------------------------------------------------

bool Int::IsOdd() {
  return (bits[0] & 0x1) == 1;
}

// ------------------------------------------------

void Int::Neg() {

	volatile unsigned char c=0;
	c = _subborrow_u64(c, 0, bits64[0], bits64 + 0);
	c = _subborrow_u64(c, 0, bits64[1], bits64 + 1);
	c = _subborrow_u64(c, 0, bits64[2], bits64 + 2);
	c = _subborrow_u64(c, 0, bits64[3], bits64 + 3);
	c = _subborrow_u64(c, 0, bits64[4], bits64 + 4);
#if NB64BLOCK > 5
	c = _subborrow_u64(c, 0, bits64[5], bits64 + 5);
	c = _subborrow_u64(c, 0, bits64[6], bits64 + 6);
	c = _subborrow_u64(c, 0, bits64[7], bits64 + 7);
	c = _subborrow_u64(c, 0, bits64[8], bits64 + 8);
#endif

}

// ------------------------------------------------

void Int::ShiftL32Bit() {

  for(int i=NB32BLOCK-1;i>0;i--) {
    bits[i]=bits[i-1];
  }
  bits[0]=0;

}

// ------------------------------------------------

void Int::ShiftL64Bit() {

	for (int i = NB64BLOCK-1 ; i>0; i--) {
		bits64[i] = bits64[i - 1];
	}
	bits64[0] = 0;

}

// ------------------------------------------------

void Int::ShiftL32BitAndSub(Int *a,int n) {

  Int b;
  int i=NB32BLOCK-1;

  for(;i>=n;i--)
    b.bits[i] = ~a->bits[i-n];
  for(;i>=0;i--)
    b.bits[i] = 0xFFFFFFFF;

  Add(&b);
  AddOne();

}

// ------------------------------------------------

void Int::ShiftL(uint32_t n) {

  if( n<64 ) {
	shiftL((unsigned char)n, bits64);
  } else {
    uint32_t nb64 = n/64;
    uint32_t nb   = n%64;
    for(uint32_t i=0;i<nb64;i++) ShiftL64Bit();
	  shiftL((unsigned char)nb, bits64);
  }

}

// ------------------------------------------------

void Int::ShiftR32Bit() {

  for(int i=0;i<NB32BLOCK-1;i++) {
    bits[i]=bits[i+1];
  }
  if(((int32_t)bits[NB32BLOCK-2])<0)
    bits[NB32BLOCK-1] = 0xFFFFFFFF;
  else
    bits[NB32BLOCK-1]=0;

}

// ------------------------------------------------

void Int::ShiftR64Bit() {

	for (int i = 0; i<NB64BLOCK - 1; i++) {
		bits64[i] = bits64[i + 1];
	}
	if (((int64_t)bits64[NB64BLOCK - 2])<0)
		bits64[NB64BLOCK - 1] = 0xFFFFFFFFFFFFFFFF;
	else
		bits64[NB64BLOCK - 1] = 0;

}

// ---------------------------------D---------------

void Int::ShiftR(uint32_t n) {

  if( n<64 ) {
    shiftR((unsigned char)n, bits64);
  } else {
    uint32_t nb64 = n/64;
    uint32_t nb   = n%64;
    for(uint32_t i=0;i<nb64;i++) ShiftR64Bit();
	  shiftR((unsigned char)nb, bits64);
  }

}

// ------------------------------------------------

void Int::Mult(Int *a) {

  Int b(this);
  Mult(a,&b);

}

// ------------------------------------------------

void Int::IMult(int64_t a) {

	// Make a positive
	if (a < 0LL) {
		a = -a;
		Neg();
	}

	imm_mul(bits64, a, bits64);

}

// ------------------------------------------------

void Int::Mult(uint64_t a) {

	imm_mul(bits64, a, bits64);

}
// ------------------------------------------------

void Int::IMult(Int *a, int64_t b) {

  Set(a);

  // Make b positive
  if (b < 0LL) {
	Neg();
	b = -b;
  }
  imm_mul(bits64, b, bits64);

}

// ------------------------------------------------

void Int::Mult(Int *a, uint64_t b) {

  imm_mul(a->bits64, b, bits64);

}

// ------------------------------------------------

void Int::Mult(Int *a,Int *b) {

  unsigned char c = 0;
  uint64_t h;
  uint64_t pr = 0;
  uint64_t carryh = 0;
  uint64_t carryl = 0;

  bits64[0] = _umul128(a->bits64[0], b->bits64[0], &pr);

  for (int i = 1; i < NB64BLOCK; i++) {
    for (int j = 0; j <= i; j++) {
      c = _addcarry_u64(c, _umul128(a->bits64[j], b->bits64[i - j], &h), pr, &pr);
      c = _addcarry_u64(c, carryl, h, &carryl);
      c = _addcarry_u64(c, carryh, 0, &carryh);
    }
    bits64[i] = pr;
    pr = carryl;
    carryl = carryh;
    carryh = 0;
  }

}

// ------------------------------------------------

void Int::Mult(Int *a,uint32_t b) {
  imm_mul(a->bits64, (uint64_t)b, bits64);
}

// ------------------------------------------------

static uint32_t bitLength(uint32_t dw) {

  uint32_t mask = 0x80000000;
  uint32_t b=0;
  while(b<32 && (mask & dw)==0) {
    b++;
    mask >>= 1;
  }
  return b;

}

// ------------------------------------------------

int Int::GetBitLength() {

  Int t(this);
  if(IsNegative())
	  t.Neg();

  int i=NB32BLOCK-1;
  while(i>=0 && t.bits[i]==0) i--;
  if(i<0) return 0;
  return (32-bitLength(t.bits[i])) + i*32;

}

// ------------------------------------------------

int Int::GetSize() {

  int i=NB32BLOCK-1;
  while(i>0 && bits[i]==0) i--;
  return i+1;

}

// ------------------------------------------------

void Int::MultModN(Int *a,Int *b,Int *n) {

  Int r;
  Mult(a,b);
  Div(n,&r);
  Set(&r);

}

// ------------------------------------------------

void Int::Mod(Int *n) {

  Int r;
  Div(n,&r);
  Set(&r);

}

// ------------------------------------------------

int Int::GetLowestBit() {

  // Assume this!=0
  int b=0;
  while(GetBit(b)==0) b++;
  return b;

}

// ------------------------------------------------

void Int::MaskByte(int n) {

  for (int i = n; i < NB32BLOCK; i++)
	  bits[i] = 0;

}

// ------------------------------------------------

void Int::Abs() {

  if (IsNegative())
    Neg();

}

// ------------------------------------------------

void Int::Rand(int nbit) {

	CLEAR();

	uint32_t nb = nbit/32;
	uint32_t leftBit = nbit%32;
	uint32_t mask = 1;
	mask = (mask << leftBit) - 1;
	uint32_t i=0;
	for(;i<nb;i++)
		bits[i]=rndl();
	bits[i]=rndl()&mask;

}

void Int::Rand(Int *min,Int *max) {
	CLEAR();
  Int diff;
  int nbit = 256;
  uint32_t nb = nbit/32;
  diff.Set(max);
  diff.Sub(min);
	uint32_t i=0;
	for(;i<nb;i++)
		bits[i]=rndl();
  this->Mod(&diff);
  this->Add(min);
}

// ------------------------------------------------

void Int::Div(Int *a,Int *mod) {

  if(a->IsGreater(this)) {
    if(mod) mod->Set(this);
    CLEAR();
    return;
  }

  if(a->IsZero()) {
    printf("Divide by 0!\n");
    return;
  }

  if(IsEqual(a)) {
    if(mod) mod->CLEAR();
    Set(&_ONE);
    return;
  }

  //Division algorithm D (Knuth section 4.3.1)

  Int rem(this);
  Int d(a);
  Int dq;
  CLEAR();

  // Size
  uint32_t dSize = d.GetSize();
  uint32_t tSize = rem.GetSize();
  uint32_t qSize = tSize - dSize + 1;

  // D1 normalize the divisor
  uint32_t shift = bitLength(d.bits[dSize-1]);
  if (shift > 0) {
    d.ShiftL(shift);
    rem.ShiftL(shift);
  }

  uint32_t  _dh    = d.bits[dSize-1];
  uint64_t  dhLong = _dh;
  uint32_t  _dl    = (dSize>1)?d.bits[dSize-2]:0;
  int sb = tSize-1;

  // D2 Initialize j
  for(int j=0; j<(int)qSize; j++) {

    // D3 Estimate qhat
    uint32_t qhat = 0;
    uint32_t qrem = 0;
    int skipCorrection = false;
    uint32_t nh = rem.bits[sb-j+1];
    uint32_t nm = rem.bits[sb-j];

    if (nh == _dh) {
      qhat = ~0;
      qrem = nh + nm;
      skipCorrection = qrem < nh;
    } else {
      uint64_t nChunk = ((uint64_t)nh << 32) | (uint64_t)nm;
      qhat = (uint32_t) (nChunk / dhLong);
      qrem = (uint32_t) (nChunk % dhLong);
    }

    if (qhat == 0)
      continue;

    if (!skipCorrection) {

      // Correct qhat
      uint64_t nl = (uint64_t)rem.bits[sb-j-1];
      uint64_t rs = ((uint64_t)qrem << 32) | nl;
      uint64_t estProduct = (uint64_t)_dl * (uint64_t)(qhat);

      if (estProduct>rs) {
        qhat--;
        qrem = (uint32_t)(qrem + (uint32_t)dhLong);
        if ((uint64_t)qrem >= dhLong) {
          estProduct = (uint64_t)_dl * (uint64_t)(qhat);
          rs = ((uint64_t)qrem << 32) | nl;
          if(estProduct>rs)
            qhat--;
        }
      }

    }

    // D4 Multiply and subtract
    dq.Mult(&d,qhat);
    rem.ShiftL32BitAndSub(&dq,qSize-j-1);
    if( rem.IsNegative() ) {
      // Overflow
      rem.Add(&d);
      qhat--;
    }

    bits[qSize-j-1] = qhat;

 }

 if( mod ) {
   // Unnormalize remainder
   rem.ShiftR(shift);
   mod->Set(&rem);
 }

}

// ------------------------------------------------

void Int::GCD(Int *a) {
    uint32_t k;
    uint32_t b;
    Int U(this);
    Int V(a);
    Int T;
    if(U.IsZero()) {
      Set(&V);
      return;
    }
    if(V.IsZero()) {
      Set(&U);
      return;
    }
    if(U.IsNegative()) U.Neg();
    if(V.IsNegative()) V.Neg();
    k = 0;
    while (U.GetBit(k)==0 && V.GetBit(k)==0)
      k++;
    U.ShiftR(k);
    V.ShiftR(k);
    if (U.GetBit(0)==1) {
      T.Set(&V);
      T.Neg();
    } else {
      T.Set(&U);
    }
    do {
      if( T.IsNegative() ) {
        T.Neg();
        b=0;while(T.GetBit(b)==0) b++;
        T.ShiftR(b);
        V.Set(&T);
        T.Set(&U);
      } else {
        b=0;while(T.GetBit(b)==0) b++;
        T.ShiftR(b);
        U.Set(&T);
      }
      T.Sub(&V);
    } while (!T.IsZero());
    // Store gcd
    Set(&U);
    ShiftL(k);
}

// ------------------------------------------------

void Int::SetBase10(const char *value) {
  CLEAR();
  Int pw((uint64_t)1);
  Int c;
  int lgth = (int)strlen(value);
  for(int i=lgth-1;i>=0;i--) {
    uint32_t id = (uint32_t)(value[i]-'0');
    c.Set(&pw);
    c.Mult(id);
    Add(&c);
    pw.Mult(10);
  }

}

// ------------------------------------------------

void  Int::SetBase16(const char *value) {
  SetBaseN(16,"0123456789ABCDEF",value);
}

// ------------------------------------------------

char* Int::GetBase10() {
  return GetBaseN(10,"0123456789");
}

// ------------------------------------------------

char* Int::GetBase16() {
  return GetBaseN(16,"0123456789abcdef");
}

// ------------------------------------------------

char* Int::GetBlockStr() {
  char *tmp =  (char*) calloc(1,256);
	char bStr[256];
	tmp[0] = 0;
	for (int i = NB32BLOCK-3; i>=0 ; i--) {
	  sprintf(bStr, "%08X", bits[i]);
	  strcat(tmp, bStr);
	  if(i!=0) strcat(tmp, " ");
	}
	return tmp;
}

// ------------------------------------------------

char * Int::GetC64Str(int nbDigit) {
  char *tmp =  (char*) calloc(1,256);
  char bStr[256];
  tmp[0] = '{';
  tmp[1] = 0;
  for (int i = 0; i< nbDigit; i++) {
    if (bits64[i] != 0) {
#ifdef _WIN64
      sprintf(bStr, "0x%016I64XULL", bits64[i]);
#else
      sprintf(bStr, "0x%" PRIx64  "ULL", bits64[i]);
#endif
    } else {
      sprintf(bStr, "0ULL");
    }
    strcat(tmp, bStr);
    if (i != nbDigit -1) strcat(tmp, ",");
  }
  strcat(tmp,"}");
  return tmp;
}

// ------------------------------------------------

void  Int::SetBaseN(int n,const char *charset,const char *value) {
  CLEAR();
  Int pw((uint64_t)1);
  Int nb((uint64_t)n);
  Int c;
  int lgth = (int)strlen(value);
  for(int i=lgth-1;i>=0;i--) {
    char *p = strchr((char*)charset,toupper(value[i]));
    if(!p) {
		printf("Invalid charset !!\n");
      return;
    }
    int id = (int)(p-charset);
    c.SetInt32(id);
    c.Mult(&pw);
    Add(&c);
    pw.Mult(&nb);
  }
}

// ------------------------------------------------

char* Int::GetBaseN(int n,const char *charset) {
  char *ret = (char*) calloc(1,1024);

  Int N(this);
  int offset = 0;
  int isNegative = N.IsNegative();
  if (isNegative) N.Neg();

  // TODO: compute max digit
  unsigned char digits[1024];
  memset(digits, 0, sizeof(digits));

  int digitslen = 1;
  for (int i = 0; i < NB64BLOCK * 8; i++) {
    unsigned int carry = N.GetByte(NB64BLOCK*8 - i - 1);
    for (int j = 0; j < digitslen; j++) {
      carry += (unsigned int)(digits[j]) << 8;
      digits[j] = (unsigned char)(carry % n);
      carry /= n;
    }
    while (carry > 0) {
      digits[digitslen++] = (unsigned char)(carry % n);
      carry /= n;
    }
  }

  // reverse
  if (isNegative)
    ret[offset++] = '-';

  for (int i = 0; i < digitslen; i++)
    ret[offset++] = charset[digits[digitslen - 1 - i]];

  if (offset == 0)
    ret[offset] = '0';
  return ret;
}

// ------------------------------------------------


int Int::GetBit(uint32_t n) {
  uint32_t byte = n>>5;
  uint32_t bit  = n&31;
  uint32_t mask = 1 << bit;
  return (bits[byte] & mask)!=0;
}

// ------------------------------------------------
char* Int::GetBase2() {
  char *ret =  (char*) calloc(1,1024);
  int k=0;
  for(int i=0;i<NB32BLOCK-1;i++) {
    unsigned int mask=0x80000000;
    for(int j=0;j<32;j++) {
      if(bits[i]&mask) ret[k]='1';
      else             ret[k]='0';
      k++;
      mask=mask>>1;
    }
  }
  ret[k]=0;
  return ret;
}
