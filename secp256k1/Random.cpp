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


#include "Random.h"

#if defined(_WIN64) && !defined(__CYGWIN__)
#else
#include <sys/random.h>
#endif

#ifdef __unix__
#ifdef __CYGWIN__
#else
#include <linux/random.h>
#endif
#endif

#define  RK_STATE_LEN 624

/* State of the RNG */
typedef struct rk_state_
{
  unsigned long key[RK_STATE_LEN];
  int pos;
} rk_state;

rk_state localState;

/* Maximum generated random value */
#define RK_MAX 0xFFFFFFFFUL

void rk_seed(unsigned long seed, rk_state *state)
{
  int pos;
  seed &= 0xffffffffUL;

  /* Knuth's PRNG as used in the Mersenne Twister reference implementation */
  for (pos=0; pos<RK_STATE_LEN; pos++)
  {
    state->key[pos] = seed;
    seed = (1812433253UL * (seed ^ (seed >> 30)) + pos + 1) & 0xffffffffUL;
  }

  state->pos = RK_STATE_LEN;
}

/* Magic Mersenne Twister constants */
#define N 624
#define M 397
#define MATRIX_A 0x9908b0dfUL
#define UPPER_MASK 0x80000000UL
#define LOWER_MASK 0x7fffffffUL

#ifdef _WIN64
// Disable "unary minus operator applied to unsigned type, result still unsigned" warning.
#pragma warning(disable : 4146)
#endif

/* Slightly optimised reference implementation of the Mersenne Twister */
inline unsigned long rk_random(rk_state *state)
{
  unsigned long y;

  if (state->pos == RK_STATE_LEN)
  {
    int i;

    for (i=0;i<N-M;i++)
    {
      y = (state->key[i] & UPPER_MASK) | (state->key[i+1] & LOWER_MASK);
      state->key[i] = state->key[i+M] ^ (y>>1) ^ (-(y & 1) & MATRIX_A);
    }
    for (;i<N-1;i++)
    {
      y = (state->key[i] & UPPER_MASK) | (state->key[i+1] & LOWER_MASK);
      state->key[i] = state->key[i+(M-N)] ^ (y>>1) ^ (-(y & 1) & MATRIX_A);
    }
    y = (state->key[N-1] & UPPER_MASK) | (state->key[0] & LOWER_MASK);
    state->key[N-1] = state->key[M-1] ^ (y>>1) ^ (-(y & 1) & MATRIX_A);

    state->pos = 0;
  }
  
  y = state->key[state->pos++];

  /* Tempering */
  y ^= (y >> 11);
  y ^= (y << 7) & 0x9d2c5680UL;
  y ^= (y << 15) & 0xefc60000UL;
  y ^= (y >> 18);

  return y;
}

inline double rk_double(rk_state *state)
{
	/* shifts : 67108864 = 0x4000000, 9007199254740992 = 0x20000000000000 */
	long a = rk_random(state) >> 5, b = rk_random(state) >> 6;
	return (a * 67108864.0 + b) / 9007199254740992.0;
}

// Initialise the random generator with the specified seed
void rseed(unsigned long seed) {
	rk_seed(seed,&localState);
	//srand(seed);
}

#if defined(_WIN64) && !defined(__CYGWIN__)
unsigned long rndl() {
	return rk_random(&localState);
}
#else
unsigned long rndl() {
	unsigned long r;
	int bytes_read = getrandom(&r, sizeof(unsigned long), GRND_NONBLOCK );
	if (bytes_read > 0) {
		return r;
	}
	else	{
		/*Fail safe */
		return rk_random(&localState);
	}
}
	
#endif

// Returns a uniform distributed double value in the interval ]0,1[
double rnd() {
	return rk_double(&localState);
}
