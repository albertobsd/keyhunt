#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>


#if  defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#elif __unix__ || __unix || __APPLE__ || __MACH__ || __CYGWIN__
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/syscall.h>
    #include <linux/random.h>
    #if defined(GRND_NONBLOCK)
        #define USE_GETRANDOM
    #endif
#endif

#include "Int.h"

static int r_state_mt_ready = 0;
static gmp_randstate_t r_state_mt;


void int_randominit()	{
	if(r_state_mt_ready)	{
		fprintf(stderr,"r_state_mt already initialized, file %s, line %i\n",__FILE__,__LINE__ - 1);
		exit(0);
	}
	mpz_t mpz_seed;
	int bytes_readed,bytes = 64;
	unsigned char seed[64];
	bytes_readed = random_bytes(seed, bytes);
	if(bytes_readed != bytes)	{
		fprintf(stderr,"Error random_bytes(), file %s, line %i\n",__FILE__,__LINE__ - 2);
		exit(0);
	}
	mpz_init(mpz_seed);
	mpz_import(mpz_seed,bytes,1,sizeof(unsigned char),0,0,seed);
	gmp_randinit_mt(r_state_mt);
	gmp_randseed(r_state_mt,mpz_seed);
	r_state_mt_ready = 1;
	mpz_clear(mpz_seed);
	memset(seed,0,bytes);
}

void Int::Rand(int nbit)	{
	if(!r_state_mt_ready)	{
		fprintf(stderr,"Error Rand(), file %s, line %i\n",__FILE__,__LINE__ - 1);
		exit(0);
	}
	mpz_urandomb(num,r_state_mt,nbit);
	mpz_setbit(num,nbit-1);
}

void Int::Rand(Int *min,Int *max)	{
	if(!r_state_mt_ready)	{
		fprintf(stderr,"Error Rand(), file %s, line %i\n",__FILE__,__LINE__ - 1);
		exit(0);
	}
	Int diff(max);
	diff.Sub(min);
	this->Rand(256);
	this->Mod(&diff);
	this->Add(min);
}

int random_bytes(unsigned char *buffer,int bytes)	{
    #if defined(_WIN32) || defined(_WIN64)
        if (!BCryptGenRandom(NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG)) {
            fprintf(stderr,"Not BCryptGenRandom available\n");
			exit(EXIT_FAILURE);
        }
		else
			return bytes;
	#elif __unix__ || __unix || __APPLE__ || __MACH__ || __CYGWIN__
		#ifdef USE_GETRANDOM
			return syscall(SYS_getrandom, buffer, bytes, GRND_NONBLOCK);
		#else
            int fd = open("/dev/urandom", O_RDONLY);
            if (fd == -1) {
				fprintf(stderr,"Not /dev/urandom available\n");
				exit(EXIT_FAILURE);
            }
            ssize_t result = read(fd, buffer, bytes);
            close(fd);
			return result;
        #endif
    #else
        #error "Unsupported platform"
    #endif
}
