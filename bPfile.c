/*
Develop by Luis Alberto
email: alberto.bsd@gmail.com

gcc -o bPfile bPfile.c -lgmp -lm

Hint: compile in the keyhunt directory
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>
#include "util.h"

uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;

struct Point {
	mpz_t x;
	mpz_t y;
};

struct Elliptic_Curve {
	mpz_t p;
  mpz_t n;
};

const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
struct Point DoublingG[256];

void Point_Doubling(struct Point *P, struct Point *R);
void Point_Addition(struct Point *P, struct Point *Q, struct Point *R);
void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m);
void Point_Negation(struct Point *A, struct Point *S);

void init_doublingG(struct Point *P);


struct Elliptic_Curve EC;
struct Point G;

int main(int argc, char **argv)	{
	mpz_t temp;
	FILE *p_file;
	char temporal[512],rawvalue[BSGS_BUFFERXPOINTLENGTH];
	long int i,m,sz;

	mpz_t M;
	struct Point point_t,P;

	if(argc < 3)	{
		printf("Create bP File usage\n");
		printf("%s <bP items> <output filename>\n\n",argv[0]);
		printf("Example to create a File with 1 Billion items:\n%s 1000000000 Pfile.bin\n",argv[0]);
		printf("If the file exists, only the missing bP items will be added○\n");
		exit(0);
	}

	mpz_init_set_str(M,argv[1],10);

  mpz_init_set_str(EC.p, EC_constant_P, 16);
  mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);


	mpz_init(point_t.x);
	mpz_init(point_t.y);

	mpz_init(temp);


	m = mpz_get_ui(M);

	mpz_init_set(P.x,G.x);
	mpz_init_set(P.y,G.y);

	p_file = fopen(argv[2],"wb");

	if(p_file == NULL)	{
		printf("Can't create file %s\n",argv[2]);
		exit(0);
	}
	/*
	fseek(p_file, 0L, SEEK_END);
	sz = ftell(p_file);
	if(sz % 32 != 0)	{
		printf("Invalid filesize\n");
		exit(0);
	}
	printf("Current numeber of items %li\n",(long int)(sz/32));
	if(m <= sz/32 )	{
		printf("The current file have %li items\n",m);
	}
	else	{
		i = m-(sz/32);
		printf("OK, items missing %li\n",i);
	}
	mpz_set_ui(temp,i)
	*/
	i = 0;
	printf("[+] precalculating %li bP elements in file %s\n",m,argv[2]);
	do {
		mpz_set(point_t.x,P.x);
		mpz_set(point_t.y,P.y);
		gmp_sprintf(temporal,"%0.64Zx",P.x);
		hexs2bin(temporal,(unsigned char *)rawvalue);
		fwrite(rawvalue,1,32,p_file);
		Point_Addition(&G,&point_t,&P);
		i++;
	} while(i < m);
}

void Point_Doubling(struct Point *P, struct Point *R)	{
	mpz_t slope, temp;
	mpz_init(temp);
	mpz_init(slope);
	if(mpz_cmp_ui(P->y, 0) != 0) {
		mpz_mul_ui(temp, P->y, 2);
		mpz_invert(temp, temp, EC.p);
		mpz_mul(slope, P->x, P->x);
		mpz_mul_ui(slope, slope, 3);
		mpz_mul(slope, slope, temp);
		mpz_mod(slope, slope, EC.p);
		mpz_mul(R->x, slope, slope);
		mpz_sub(R->x, R->x, P->x);
		mpz_sub(R->x, R->x, P->x);
		mpz_mod(R->x, R->x, EC.p);
		mpz_sub(temp, P->x, R->x);
		mpz_mul(R->y, slope, temp);
		mpz_sub(R->y, R->y, P->y);
		mpz_mod(R->y, R->y, EC.p);
	} else {
		mpz_set_ui(R->x, 0);
		mpz_set_ui(R->y, 0);
	}
	mpz_clear(temp);
	mpz_clear(slope);
}

void Point_Addition(struct Point *P, struct Point *Q, struct Point *R)	{
	mpz_t PA_temp,PA_slope;
	mpz_init(PA_temp);
	mpz_init(PA_slope);
	mpz_mod(Q->x, Q->x, EC.p);
	mpz_mod(Q->y, Q->y, EC.p);
	mpz_mod(P->x, P->x, EC.p);
	mpz_mod(P->y, P->y, EC.p);
	if(mpz_cmp_ui(P->x, 0) == 0 && mpz_cmp_ui(P->y, 0) == 0) {
		mpz_set(R->x, Q->x);
		mpz_set(R->y, Q->y);
	}
	else	{
    /*  This is commented because Q never 0,0, always is kG point*/
    /*
		if(mpz_cmp_ui(Q->x, 0) == 0 && mpz_cmp_ui(Q->y, 0) == 0) {
			mpz_set(R->x, P->x);
			mpz_set(R->y, P->y);
		}
		else	{
    */
			if(mpz_cmp_ui(Q->y, 0) != 0) {
				mpz_sub(PA_temp, EC.p, Q->y);
				mpz_mod(PA_temp, PA_temp, EC.p);
			}
			else	{
				mpz_set_ui(PA_temp, 0);
			}
			if(mpz_cmp(P->y, PA_temp) == 0 && mpz_cmp(P->x, Q->x) == 0) {
				mpz_set_ui(R->x, 0);
				mpz_set_ui(R->y, 0);
			}
			else	{
				if(mpz_cmp(P->x, Q->x) == 0 && mpz_cmp(P->y, Q->y) == 0)	{
					Point_Doubling(P, R);
				}
				else {
					mpz_set_ui(PA_slope, 0);
					mpz_sub(PA_temp, P->x, Q->x);
					mpz_mod(PA_temp, PA_temp, EC.p);
					mpz_invert(PA_temp, PA_temp, EC.p);
					mpz_sub(PA_slope, P->y, Q->y);
					mpz_mul(PA_slope, PA_slope, PA_temp);
					mpz_mod(PA_slope, PA_slope, EC.p);
					mpz_mul(R->x, PA_slope, PA_slope);
					mpz_sub(R->x, R->x, P->x);
					mpz_sub(R->x, R->x, Q->x);
					mpz_mod(R->x, R->x, EC.p);
					mpz_sub(PA_temp, P->x, R->x);
					mpz_mul(R->y, PA_slope, PA_temp);
					mpz_sub(R->y, R->y, P->y);
					mpz_mod(R->y, R->y, EC.p);
				}
			}
		//}
	}
	mpz_clear(PA_temp);
	mpz_clear(PA_slope);
}

void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m)	{
	char strtemp[65];
	struct Point SM_T,SM_Q;
	long no_of_bits, i;
	no_of_bits = mpz_sizeinbase(m, 2);
	mpz_init_set_ui(SM_Q.x,0);
	mpz_init_set_ui(SM_Q.y,0);
	mpz_init_set_ui(SM_T.x,0);
	mpz_init_set_ui(SM_T.y,0);
	mpz_set_ui(R->x, 0);
	mpz_set_ui(R->y, 0);
	if(mpz_cmp_ui(m, 0) != 0)	{
		mpz_set(SM_Q.x, P.x);
		mpz_set(SM_Q.y, P.y);
		for(i = 0; i < no_of_bits; i++) {
			if(mpz_tstbit(m, i))	{
				mpz_set(SM_T.x, R->x);
				mpz_set(SM_T.y, R->y);
				mpz_set(SM_Q.x,DoublingG[i].x);
				mpz_set(SM_Q.y,DoublingG[i].y);
				Point_Addition(&SM_T, &SM_Q, R);
			}
		}
	}
	mpz_clear(SM_T.x);
	mpz_clear(SM_T.y);
	mpz_clear(SM_Q.x);
	mpz_clear(SM_Q.y);
}

void Point_Negation(struct Point *A, struct Point *S)	{
	mpz_sub(S->y, EC.p, A->y);
	mpz_set(S->x, A->x);
}

void init_doublingG(struct Point *P)	{
	int i = 0;
	mpz_init(DoublingG[i].x);
	mpz_init(DoublingG[i].y);
	mpz_set(DoublingG[i].x,P->x);
	mpz_set(DoublingG[i].y,P->y);
	i = 1;
	while(i < 256){
		mpz_init(DoublingG[i].x);
		mpz_init(DoublingG[i].y);
		Point_Doubling(&DoublingG[i-1] ,&DoublingG[i]);
		mpz_mod(DoublingG[i].x, DoublingG[i].x, EC.p);
		mpz_mod(DoublingG[i].y, DoublingG[i].y, EC.p);
		i++;
	}
}
