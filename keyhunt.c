/*
Develop by Luis Alberto
email: alberto.bsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmp.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include "keccak/keccak-tiny.h"
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"
#include "bloom/bloom.h"
#include "util.h"


#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define CRYPTO_ETH 2
#define CRYPTO_ALL 3


struct Point {
	mpz_t x;
	mpz_t y;
};

struct Elliptic_Curve {
	mpz_t p;
  mpz_t n;
};

struct tothread {
  int nt; //Number thread
  char *rs; //range start
  char *rpt;  //rng per thread
};

const char *version = "0.1.20201221";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
struct Point DoublingG[256];

void Point_Doubling(struct Point *P, struct Point *R);
void Point_Addition(struct Point *P, struct Point *Q, struct Point *R);
void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m);
void Point_Negation(struct Point A, struct Point *S);
int searchbinary(char *BUFFER,char *data,int length,int N);
void quicksort(char *arr, int low, int high);
int partition (char *arr, int low, int high);
void swap(char *a,char *b);


void *thread_process(void *vargp);
void *thread_process_range(void *vargp);

void init_doublingG(struct Point *P);
char *pubkeytopubaddress(char *pkey,int length);
char *pubkeytopubaddress_eth(char *pkey,int length);
char *bit_range_str_min;
char *bit_range_str_max;



const char *modes[2] = {"xpoint","address"};
const char *cryptos[3] = {"btc","eth","all"};
const char *default_filename = "addresses.txt";

pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_range;
pthread_mutex_t write_random;

struct Elliptic_Curve EC;
struct bloom bloom;
struct Point G;
unsigned int *steps = NULL;
unsigned int *ends = NULL;
char *DATABUFFER;
int N = 0;
gmp_randstate_t state;

uint64_t N_SECUENTIAL_MAX = 0xffffffff;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;
int DEBUGCOUNT = 0x100000;
int OUTPUTSECONDS = 30;
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGHELP = 0;
int FLAGFILE = 0;
int FLAGVANITY = 0;
int FLAGMODE = 1;
int FLAGCRYPTO = 0;
int FLAGALREADYSORTED = 0;

int len_vanity;
int bitrange;
char *vanity;
char *range_start;
char *range_end;

int main(int argc, char **argv)	{
  struct tothread *tt;  //tothread
  Tokenizer t;  //tokenizar
  char *filename;
	FILE *fd;
  char *hextemp,*aux,*aux2;
	int readed,i,s,continue_flag,check_flag,r,lenaux,lendiff;
  uint64_t total = 0;
	uint32_t seconds = 0;
  mpz_t n_range_start;
  mpz_t n_range_end;
  mpz_t n_range_diff;
  mpz_t n_range_per_threads;
  mpz_t n_range_aux;
  mpz_t n_range_r;
  int c;

  mpz_init_set_str(EC.p, EC_constant_P, 16);
  mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
  while ((c = getopt (argc, argv, "ehRb:c:f:g:m:n:r:s:t:v:")) != -1) {
    switch(c) {
			case 'h':
        FLAGHELP = 1;
        printf("keyhunt version %s\n\n",version);
        printf("\nUsage:\n-h\t\tshow this help\n");
				printf("-b bits\t\tFor some puzzles you only need some numbers of bits in the test keys.\n");
				printf("\t\tThis option only is valid with the Random option -R\n");
				printf("-c crypto\tSearch for specific crypo. < btc, eth, all > valid only w/ -m address \n");
				printf("\t\teth option is under develop sorry :(\n");
				printf("-e\t\tThe file is already Sorted descendent. This skip the sorting process.\n");
				printf("\t\tYour file MUST be sordted if no you are going to lose collisions\n");
        printf("-f filename\tSpecify filename with addresses or xpoint\n");
				printf("-g debugcount\tJust for the stats, mark as counted every debugcount keys\n");
        printf("-m mode\t\tmode of search for cryptos. < xpoint , address >  default: address (more slow)\n");
				printf("-n uptoN\tCheck for N secuential numbers before the random chossen this only work with -R option\n");
        printf("-r SR:EN\tStarRange:EndRange, the end range can be omited for search from start range to N-1 ECC value\n");
				printf("-R\t\tRandom/Secuential this is the default behaivor, can't use this with range option -r\n");
        printf("-s ns\t\tNumber of seconds for the stats output, 0 to omit output.\n");
        printf("-t tn\t\tThreads number, must be positive integer\n\n");
				printf("-v va\t\tSearch for vanity Address, only with -m address\n");
        printf("\nExample\n\n");
        printf("%s -t 16 -r 00000001:FFFFFFFF -s 0\n\n",argv[0]);
        printf("This line run the program with 16 threads from the range 00000001 to FFFFFFFF without stats output\n\n");
        printf("Developed by AlbertoBSD\tTips BTC: 1H3TAVNZFZfiLUp9o9E93oTVY9WgYZ5knX\n\n");
        exit(0);
      break;
			case 'b':
				bitrange = strtol(optarg,NULL,10);
				if(bitrange > 0 && bitrange <=256 )	{
					bit_range_str_min = malloc(bitrange+1);
					bit_range_str_max = malloc(bitrange+1);
					if(bit_range_str_min == NULL||bit_range_str_max == NULL)	{
						fprintf(stderr,"erorr malloc()\n");
						exit(0);
					}
					memset(bit_range_str_min,'1',bitrange);
					memset(bit_range_str_max,'1',bitrange);
					bit_range_str_min[0] = '0';
					printf("bit min range: %s\n",bit_range_str_min);
					printf("bit max range: %s\n",bit_range_str_max);
					FLAGBITRANGE = 1;
				}
        else	{
					printf("invalid bits param: %s\n",optarg);
				}
      break;
      case 'c':
        switch(indexOf(optarg,cryptos,3)) {
            case 0: //btc
              FLAGCRYPTO = CRYPTO_BTC;
              printf("Setting search for btc adddress\n");
            break;
            case 1: //eth
              FLAGCRYPTO = CRYPTO_ETH;
              printf("Setting search for eth adddress\n");
            break;
            case 2: //all
              FLAGCRYPTO = CRYPTO_ALL;
              printf("Setting search for all cryptos\nFor each crypto there are many hash and base_algo operations  and the performance down slow\n");
            break;
            default:
              FLAGCRYPTO = CRYPTO_NONE;
              printf("Unknow crypto value %s\n",optarg);
            break;
        }
        optarg;
      break;
			case 'e':
				FLAGALREADYSORTED = 1;
			break;
			case 'f':
        FLAGFILE = 1;
        filename = optarg;
      break;
			case 'g':
        DEBUGCOUNT = strtol(optarg,NULL,10);
				if(DEBUGCOUNT == 0)	{
					DEBUGCOUNT = 0x100000;
					fprintf(stderr,"invalid -g option value: %s\n",optarg);
				}
      break;
      case 'm':
        switch(indexOf(optarg,modes,2)) {
          case 0: //xpoint
            FLAGMODE = 0;
            printf("Setting mode xpoint\n");
          break;
          case 1: //address
            FLAGMODE = 1;
            printf("Setting mode address\n");
          break;
          default:
            FLAGMODE = 1;
            printf("Unknow mode value %s\n",optarg);
          break;
        }
      break;
			case 'n':
				N_SECUENTIAL_MAX = strtol(optarg,NULL,10);
				if(N_SECUENTIAL_MAX <= 0)	{
					N_SECUENTIAL_MAX = 0xFFFFFFFF;
				}
				printf("Setting N upto: %u\n",N_SECUENTIAL_MAX);
			break;
      case 'v':
        FLAGVANITY = 1;
        vanity = optarg;
        len_vanity = strlen(optarg);
      break;
			case 'R':
				FLAGRANGE = 0;
				printf("Setting random mode\n");
			break;
      case 'r':
        if(optarg != NULL)  {
          stringtokenizer(optarg,&t);
          switch(t.n)  {
            case 1:
              range_start = nextToken(&t);
              if(isValidHex(range_start)) {
                  FLAGRANGE = 1;
                  range_end = (char*) EC_constant_N;
              }
              else  {
                printf("Invalid hexstring : %s\n",range_start);
              }
            break;
            case 2:
              range_start = nextToken(&t);
              range_end   = nextToken(&t);
              if(isValidHex(range_start) && isValidHex(range_end)) {
                  FLAGRANGE = 1;
              }
              else  {
                if(isValidHex(range_start)) {
                  printf("Invalid hexstring : %s\n",range_start);
                }
                else  {
                  printf("Invalid hexstring : %s\n",range_end);
                }
              }
            break;
            default:
              printf("Unknow number of Range Params: %i\n",t.n);
            break;
          }
        }
      break;
      case 's':
        OUTPUTSECONDS = strtol(optarg,NULL,10);
        if(OUTPUTSECONDS < 0)  {
          OUTPUTSECONDS = 30;
        }
        if(OUTPUTSECONDS == 0)  {
          printf("Turn off stats output\n");
        }
        else  {
          printf("Stats output every %u seconds\n",OUTPUTSECONDS);
        }
      break;
			case 't':
        NTHREADS = strtol(optarg,NULL,10);
        if(NTHREADS <= 0)  {
          NTHREADS = 1;
        }
        printf((NTHREADS > 1) ? "Setting %u threads\n": "Setting %u thread\n",NTHREADS);
      break;
      default:
        printf("Unknow opcion %c\n",c);
        if(optarg == NULL){
          printf("optarg es NULL\n");
        }
        else  {
          printf("optarg No es NULL: %s\n",optarg);
        }
      break;
    }
  }
	if(DEBUGCOUNT  > N_SECUENTIAL_MAX)	{
		DEBUGCOUNT = N_SECUENTIAL_MAX - 1;
		//printf("Setting debug count to %u",N_SECUENTIAL_MAX);
	}
  if(FLAGMODE == 1 && FLAGCRYPTO == CRYPTO_NONE) {  //When none crypto is defined the default search is for Bitcoin
    FLAGCRYPTO = CRYPTO_BTC;
    printf("Setting search for btc adddress\n");
  }
  if(FLAGFILE == 0) {
    filename =(char*) default_filename;
  }
  if(FLAGRANGE) {
    mpz_init_set_str(n_range_start,range_start,16);
    mpz_init_set_str(n_range_end,range_end,16);
    if(mpz_cmp(n_range_start,n_range_end) != 0 ) {
      if(mpz_cmp(n_range_start,EC.n) < 0 && mpz_cmp(n_range_end,EC.n) <= 0)  {
        if(mpz_cmp(n_range_start,n_range_end) > 0) {
          printf("Opps, start and range can't be great than End range. Swapping them\n");
          mpz_init_set(n_range_aux,n_range_start);
          mpz_set(n_range_start,n_range_end);
          mpz_set(n_range_end,n_range_aux);
          mpz_clear(n_range_aux);
        }
        mpz_init(n_range_per_threads);
        mpz_init(n_range_diff);
        mpz_init(n_range_r);
        mpz_sub(n_range_diff,n_range_end,n_range_start);
        mpz_fdiv_q_ui(n_range_per_threads,n_range_diff,NTHREADS);
        mpz_mod_ui(n_range_r,n_range_diff,NTHREADS);
      }
      else  {
        printf("Start and End range can't be great than N\nFallback to random mode!\n");
        FLAGRANGE = 0;
      }
    }
    else  {
      printf("Start and End range can't be the same\nFallback to random mode!\n");
      FLAGRANGE = 0;
    }
  }
  fd = fopen(filename,"rb");
  if(fd == NULL)	{
    fprintf(stderr,"cant open file %s\n",filename);
    exit(0);
  }
  N =0;
  aux = malloc(1000);
  while(!feof(fd))  {
    hextemp = fgets(aux,1000,fd);
		if(hextemp == aux)	{
	    trim(aux," \t\n\r");
			//printf("reading %s\n",aux);
	    r = strlen(aux);
	    if(r > 10)  { //Any length for invalid Address?
	      if(r > MAXLENGTHADDRESS)  {
	        MAXLENGTHADDRESS = r;
	      }
	      N++;
	    }
		}
  }
  free(aux);
  fseek(fd,0,SEEK_SET);
  if(FLAGMODE == 0)  {
    MAXLENGTHADDRESS = 32;
  }
  do {
		DATABUFFER = malloc(MAXLENGTHADDRESS*N);
	} while(DATABUFFER == NULL);
  printf("init bloom filter for %u elements\n",N);
	if(2*N < 1000)	{
		if(bloom_init(&bloom,1000,0.001)  == 1){
			fprintf(stderr,"error bloom_init\n");
			exit(0);
		}
	}
	else	{
		if(bloom_init(&bloom,2*N,0.001)  == 1){
			fprintf(stderr,"error bloom_init\n");
			exit(0);
		}
	}
  printf("loading data and making bloomfilter\n");
	i = 0;
	aux = malloc(2*MAXLENGTHADDRESS);
  if(FLAGMODE)  { //Address
		aux = malloc(2*MAXLENGTHADDRESS);
    while(i < N)  {
			memset(aux,0,2*MAXLENGTHADDRESS);
  		memset(DATABUFFER + (i*MAXLENGTHADDRESS),0,MAXLENGTHADDRESS);
      hextemp = fgets(aux,2*MAXLENGTHADDRESS,fd);
			if(hextemp == aux)	{
	      trim(aux," \t\n\r");
	      bloom_add(&bloom, aux,MAXLENGTHADDRESS);
				memcpy(DATABUFFER + (i*MAXLENGTHADDRESS),aux,MAXLENGTHADDRESS);
	      i++;
			}
			else	{
				trim(aux," \t\n\r");
				printf("Omiting line : %s\n",aux);
			}
    }
  }
  else  {
		aux = malloc(3*MAXLENGTHADDRESS);
    while(i < N)  {
			memset(aux,0,3*MAXLENGTHADDRESS);
      hextemp = fgets(aux,3*MAXLENGTHADDRESS,fd);
			if(hextemp == aux)	{
	      trim(aux," \t\n\r");
				lenaux = strlen(aux);
				memset(DATABUFFER + (i*MAXLENGTHADDRESS),0,MAXLENGTHADDRESS);
				if(isValidHex(aux)) {
					if(lenaux <= 64)	{
						if(lenaux < 64)	{
							aux2 = calloc(3*MAXLENGTHADDRESS,1);
							lendiff = 64 - lenaux;
							memcpy(aux2+lendiff,aux,lenaux);
							memset(aux2,'0',lendiff);
							memcpy(aux,aux2,3*MAXLENGTHADDRESS);
							free(aux2);
						}
						if(hexs2bin(aux,DATABUFFER + (i*MAXLENGTHADDRESS)))	{
								bloom_add(&bloom, DATABUFFER + (i*MAXLENGTHADDRESS),MAXLENGTHADDRESS);
						}
						else	{
							printf("error hexs2bin\n");
						}
					}
					else	{
						printf("Omiting line : %s\n",aux);
					}
	      }
	      else  {
	        printf("Ignoring invalid hexvalue %s\nAre you sure that your file are X points?",aux);
	      }
	      i++;
			}
			else	{
				printf("Omiting line : %s\n",aux);
			}
    }
  }
	free(aux);
  fclose(fd);
	printf("bloomfilter completed\n");
  printf("sorting data\n");
	if(FLAGALREADYSORTED)	{
	  printf("File mark already sorted, skipping sort proccess\n");
	}
	else	{
		quicksort(DATABUFFER,0,N-1);
	}
  printf("%i values were loaded and sorted\n",N);

	init_doublingG(&G);

  if(FLAGRANGE == 0)  {
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL));
  }
	steps = (unsigned int *) calloc(NTHREADS,sizeof(int));
  ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
	tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
  if(FLAGRANGE == 0)  {
  	for(i= 0;i < NTHREADS; i++)  {
      tt = malloc(sizeof(struct tothread));
      tt->nt = i;
      steps[i] = 0;
  		s = pthread_create(&tid[i],NULL,thread_process,(void *)tt);
  		if(s != 0)  {
  			fprintf(stderr,"error: pthread_create thread_process\n");
  		}
  	}
  }
  else  {
    for(i= 0;i < NTHREADS; i++)  {
      if(i == (NTHREADS)-1) {
        mpz_add(n_range_per_threads,n_range_per_threads,n_range_r);
      }
      tt = malloc(sizeof(struct tothread));
      tt->nt = i;
      tt->rs = malloc(65);
      mpz_get_str(tt->rs,16,n_range_start);

      tt->rpt = malloc(65);
      mpz_get_str(tt->rpt,16,n_range_per_threads);

      steps[i] = 0;
  		s = pthread_create(&tid[i],NULL,thread_process_range,(void *)tt);
  		if(s != 0)  {
  			fprintf(stderr,"error: pthread_create thread_process\n");
  		}
      mpz_add(n_range_start,n_range_start,n_range_per_threads);
  	}
  }
  if(FLAGRANGE) {
    mpz_clear(n_range_per_threads);
    mpz_clear(n_range_start);
    mpz_clear(n_range_end);
    mpz_clear(n_range_diff);
    mpz_clear(n_range_r);
  }
  continue_flag = 1;
  do  {
    sleep(1);
    seconds+=1;
    if(FLAGRANGE) {
      check_flag = 1;
      for(i = 0; i <NTHREADS && check_flag; i++) {
        check_flag &= ends[i];
      }
      if(check_flag)  {
        continue_flag = 0;
      }
    }
    if(OUTPUTSECONDS > 0){
        if(seconds % OUTPUTSECONDS == 0) {
        total = 0;
        i = 0;
        while(i < NTHREADS) {
          total +=(uint64_t)( (uint64_t)steps[i] * (uint64_t)DEBUGCOUNT);
          i++;
        }
        printf("Total %llu keys in %lu secods: %lu keys/s\n",total,seconds,(uint64_t) ((uint64_t)total/(uint64_t)seconds));
      }
    }
  }while(continue_flag);
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

void Point_Negation(struct Point A, struct Point *S)	{
	struct Point PN_Q;
	mpz_t PN_temp;
	mpz_init(PN_temp);
	mpz_init(PN_Q.x);
	mpz_init(PN_Q.y);
	mpz_set(PN_Q.x, A.x);
	mpz_set(PN_Q.y, A.y);
	mpz_sub(PN_temp, EC.p, PN_Q.y);
	mpz_set(S->x, PN_Q.x);
	mpz_set(S->y, PN_temp);
	mpz_clear(PN_temp);
	mpz_clear(PN_Q.x);
	mpz_clear(PN_Q.y);
}

/*
	Precalculate G Doublings for Scalar_Multiplication
*/
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
char *pubkeytopubaddress_eth(char *pkey,int length)	{
		char *temp,*pubaddress = calloc(MAXLENGTHADDRESS,1);
		char *digest = malloc(32);
		if(digest == NULL || pubaddress == NULL)	{
			fprintf(stderr,"error malloc()\n");
			exit(0);
		}
		pubaddress[0] = '0';
		pubaddress[1] = 'x';
		shake256(digest, 256, pkey, length);
		temp = tohex(digest+12,20);
		strcpy(pubaddress+2,temp);
		free(temp);
		free(digest);
		return pubaddress;
}

char *pubkeytopubaddress(char *pkey,int length)	{
	char *pubaddress = calloc(MAXLENGTHADDRESS+10,1);
	char *digest = malloc(60);
	long unsigned int pubaddress_size = MAXLENGTHADDRESS+10;
	if(pubaddress == NULL || digest == NULL)	{
		fprintf(stderr,"error malloc()\n");
		exit(0);
	}
	memset(digest,0,60);
	//digest [000...0]
 	sha256(pkey, length, digest);
	//digest [SHA256 32 bytes+000....0]
	RMD160Data(digest,32, digest+1);
	//digest [? +RMD160 20 bytes+????000....0]
	digest[0] = 0;
	//digest [0 +RMD160 20 bytes+????000....0]
	sha256(digest, 21, digest+21);
	//digest [0 +RMD160 20 bytes+SHA256 32 bytes+....0]
	sha256(digest+21, 32, digest+21);
	//digest [0 +RMD160 20 bytes+SHA256 32 bytes+....0]
	if(!b58enc(pubaddress,&pubaddress_size,digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
	free(digest);
	return pubaddress;	// pubaddress need to be free by te caller funtion
}

int searchbinary(char *buffer,char *data,int length,int N) {
	char *temp_read;
  int r = 0,rcmp,current_offset,half,min,max,current;
  min = 0;
  current = 0;
  max = N;
  half = N;
	//c =0;
  while(!r && half >= 1) {
    half = half/2;
		temp_read = buffer + ((current+half) * length);
    rcmp = memcmp(data,temp_read,length);
    if(rcmp == 0)  {
      r = 1;  //Found!!
    }
    else  {
      if(rcmp < 0) { //data < temp_read
        max = (max-half-1);
      }
      else  { // data > temp_read
        min = (min+half+1);
      }
			current = min;
    }
		//c++;
  }
	//printf("Searchs %i\n",c);
  return r;
}

void *thread_process(void *vargp)	{
  struct tothread *tt;
	struct Point R,temporal;
	uint64_t count = 0;
	int r,thread_number;
	char *hexstrpoint;
	char *public_key_compressed,*public_key_uncompressed;
  char *hextemp,*public_key_compressed_hex,*public_key_uncompressed_hex;
  char *eth_address;
  char *public_address_compressed,*public_address_uncompressed;
	unsigned long longtemp;
	FILE *keys,*range_file,*vanityKeys;
	mpz_t random_key_mpz,mpz_bit_range_min,mpz_bit_range_max,mpz_bit_range_diff;
	mpz_init(random_key_mpz);
	mpz_init(R.x);
	mpz_init(R.y);
	mpz_init(temporal.x);
	mpz_init(temporal.y);
	if(FLAGBITRANGE)	{
		mpz_init_set_str(mpz_bit_range_min,bit_range_str_min,2);
		mpz_init_set_str(mpz_bit_range_max,bit_range_str_max,2);
		mpz_init(mpz_bit_range_diff);
		mpz_sub(mpz_bit_range_diff,mpz_bit_range_max,mpz_bit_range_min);
	}
  public_key_compressed = malloc(33);
  public_key_uncompressed = malloc(65);
	hexstrpoint = malloc(65);
  tt = (struct tothread *)vargp;
  thread_number = tt->nt;
  free(tt);
	if(public_key_compressed == NULL || public_key_uncompressed == NULL || hexstrpoint == NULL)	{
		fprintf(stderr,"error malloc!\n");
		exit(0);
	}
	do {
		pthread_mutex_lock(&write_random);
		if(FLAGBITRANGE)	{
			mpz_urandomm(random_key_mpz,state,mpz_bit_range_diff);
			mpz_add(random_key_mpz,random_key_mpz,mpz_bit_range_min);
		}
		else	{
	    mpz_urandomm(random_key_mpz,state,EC.n);
		}
		pthread_mutex_unlock(&write_random);
    hextemp  = malloc(65);
    mpz_get_str(hextemp,16,random_key_mpz);
		pthread_mutex_lock(&write_range);
		printf("Thread %i : Setting up base key: %s\n",thread_number,hextemp);
		range_file = fopen("./ranges.txt","a+");
		if(range_file != NULL)	{
			fprintf(range_file,"%s\n",hextemp);
			fclose(range_file);
		}
		pthread_mutex_unlock(&write_range);
		free(hextemp);
		Scalar_Multiplication(G, &R, random_key_mpz);
    count = 0;
    public_key_uncompressed[0] = 0x04;
		do {
			mpz_set(temporal.x,R.x);
			mpz_set(temporal.y,R.y);

			gmp_sprintf(hexstrpoint,"%0.64Zx",R.x);
			hexs2bin(hexstrpoint,public_key_compressed+1);

      if(mpz_tstbit(R.y, 0) == 0)	{	// Even
        public_key_compressed[0] = 0x02;
      }
      else	{	//Odd
        public_key_compressed[0] = 0x03;
      }
      if(FLAGMODE ) { // FLAGMODE == 1 search for address but for what crypto ?
        if( (FLAGCRYPTO & CRYPTO_BTC) != 0) {
					memcpy(public_key_uncompressed+1,public_key_compressed+1,32);
					gmp_sprintf(hexstrpoint,"%0.64Zx",R.y);
					hexs2bin(hexstrpoint,public_key_uncompressed+33);

          public_address_compressed = pubkeytopubaddress(public_key_compressed,33);
          public_address_uncompressed = pubkeytopubaddress(public_key_uncompressed,65);
					/*
					printf("Testing for %s\n",public_address_compressed);
					printf("Testing for %s\n",public_address_uncompressed);
					*/
          if(FLAGVANITY)  {
            if(strncmp(public_address_uncompressed,vanity,len_vanity) == 0)	{
              hextemp = malloc(65);
              mpz_get_str(hextemp,16,random_key_mpz);
      				vanityKeys = fopen("vanitykeys.txt","a+");
      				if(vanityKeys != NULL)	{
      					fprintf(vanityKeys,"PrivKey: %s\n%s\n",hextemp,public_address_uncompressed);
      					fclose(vanityKeys);
      				}
              free(hextemp);
      			}
            if(strncmp(public_address_compressed,vanity,len_vanity) == 0)	{
              hextemp = malloc(65);
              mpz_get_str(hextemp,16,random_key_mpz);
      				vanityKeys = fopen("vanitykeys.txt","a+");
      				if(vanityKeys != NULL)	{
      					fprintf(vanityKeys,"PrivKey: %s\n%s\n",hextemp,public_address_compressed);
      					fclose(vanityKeys);
      				}
              free(hextemp);
      			}
          }
          r = bloom_check(&bloom,public_address_compressed,MAXLENGTHADDRESS);
    			if(r) {
    				r = searchbinary(DATABUFFER,public_address_compressed,MAXLENGTHADDRESS,N);
    	      if(r) {
              hextemp = malloc(65);
              mpz_get_str(hextemp,16,random_key_mpz);
              public_key_compressed_hex = tohex(public_key_compressed,33);
    					pthread_mutex_lock(&write_keys);
    					keys = fopen("keys.txt","a+");
    					if(keys != NULL)	{
    						fprintf(keys,"PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_compressed_hex,public_address_compressed);
    						fclose(keys);
    					}
    					printf("HIT!! PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_compressed_hex,public_address_compressed);
    					pthread_mutex_unlock(&write_keys);
              free(public_key_compressed_hex);
              free(hextemp);
    	      }
    			}

          r = bloom_check(&bloom,public_address_uncompressed,MAXLENGTHADDRESS);
    			if(r) {
    				r = searchbinary(DATABUFFER,public_address_uncompressed,MAXLENGTHADDRESS,N);
    	      if(r) {
              hextemp = malloc(65);
              mpz_get_str(hextemp,16,random_key_mpz);
              public_key_uncompressed_hex = tohex(public_key_uncompressed,65);
    					pthread_mutex_lock(&write_keys);
    					keys = fopen("keys.txt","a+");
    					if(keys != NULL)	{
    						fprintf(keys,"PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_uncompressed_hex,public_address_uncompressed);
    						fclose(keys);
    					}
    					printf("HIT!! PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_uncompressed_hex,public_address_uncompressed);
    					pthread_mutex_unlock(&write_keys);
              free(public_key_uncompressed_hex);
              free(hextemp);
    	      }
    			}
          free(public_address_compressed);
          free(public_address_uncompressed);
        }
				//printf("Resultado %i\n",FLAGCRYPTO & CRYPTO_ETH);
        if( (FLAGCRYPTO & CRYPTO_ETH) != 0) {
					/*
					mpz_export((public_key_uncompressed+1),&longtemp,1,8,1,0,R.x);
          mpz_export((public_key_uncompressed+33),&longtemp,1,8,1,0,R.y);
          public_address_uncompressed = pubkeytopubaddress_eth(public_key_uncompressed+1,64);
					//printf("Testing for %s\n",public_address_uncompressed);
					r = bloom_check(&bloom,public_address_uncompressed,MAXLENGTHADDRESS);
    			if(r) {
    				r = searchbinary(DATABUFFER,public_address_uncompressed,MAXLENGTHADDRESS,N);
    	      if(r) {
              hextemp = malloc(65);
              mpz_get_str(hextemp,16,random_key_mpz);
              public_key_uncompressed_hex = tohex(public_key_uncompressed+1,64);
    					pthread_mutex_lock(&write_keys);
    					keys = fopen("keys.txt","a+");
    					if(keys != NULL)	{
    						fprintf(keys,"PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_uncompressed_hex,public_address_uncompressed);
    						fclose(keys);
    					}
    					printf("HIT!! PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_uncompressed_hex,public_address_uncompressed);
    					pthread_mutex_unlock(&write_keys);
              free(public_key_uncompressed_hex);
              free(hextemp);
    	      }
						free(public_address_uncompressed);
					}
					*/
				}
      }
      else  {   //FLAGMODE  == 0

        r = bloom_check(&bloom,public_key_compressed+1,MAXLENGTHADDRESS);
  			if(r) {
  				r = searchbinary(DATABUFFER,public_key_compressed+1,MAXLENGTHADDRESS,N);
  	      if(r) {
            hextemp = malloc(65);
            mpz_get_str(hextemp,16,random_key_mpz);
            public_key_compressed_hex = tohex(public_key_compressed,33);
  					pthread_mutex_lock(&write_keys);
  					keys = fopen("./keys.txt","a+");
  					if(keys != NULL)	{
  						fprintf(keys,"PrivKey: %s\npubkey: %s\n",hextemp,public_key_compressed_hex);
  						fclose(keys);
  					}
  					printf("HIT!! PrivKey: %s\npubkey: %s\n",hextemp,public_key_compressed_hex);
  					pthread_mutex_unlock(&write_keys);
            free(public_key_compressed_hex);
            free(hextemp);
  	      }
  			}
      }
			count++;
			if(count %  DEBUGCOUNT == 0)	{
        steps[thread_number]++;
			}
			mpz_add_ui(random_key_mpz,random_key_mpz,1);
			Point_Addition(&temporal,&G,&R);
		}while(count <= N_SECUENTIAL_MAX);
	} while(1);
	printf("Testing Keys %lu\n",count);
}

void *thread_process_range(void *vargp)	{
  struct tothread *tt;
	struct Point R,temporal;
	uint64_t count = 0;
	int r,thread_number,found = 0;
	char *hexstrpoint;
  char *public_key_compressed,*public_key_uncompressed;
  char *hextemp,*public_key_compressed_hex,*public_key_uncompressed_hex;
  char *eth_address;
  char *public_address_compressed,*public_address_uncompressed;
	unsigned long longtemp;
	FILE *keys,*range_file,*vanityKeys;
	mpz_t key_mpz,max_mpz;
	mpz_init(R.x);
	mpz_init(R.y);
	mpz_init(temporal.x);
	mpz_init(temporal.y);
  tt = (struct tothread *) vargp;
  thread_number = tt->nt;

  mpz_init_set_str(key_mpz,tt->rs,16);
  mpz_init_set_str(max_mpz,tt->rpt,16);
  mpz_add(max_mpz,key_mpz,max_mpz);

  public_key_compressed = malloc(33);
  public_key_uncompressed = malloc(65);
	hexstrpoint = malloc(65);

	if(public_key_compressed == NULL || public_key_uncompressed == NULL || hexstrpoint == NULL)	{
		fprintf(stderr,"error malloc!\n");
		exit(0);
	}
	printf("Thread %i : Setting up base key: %s\n",thread_number,tt->rs);
  pthread_mutex_lock(&write_range);
  range_file = fopen("./ranges.txt","a+");
  if(range_file != NULL)	{
    fprintf(range_file,"%s\n",tt->rs);
    fclose(range_file);
  }
  pthread_mutex_unlock(&write_range);
  free(tt->rs);
  free(tt->rpt);
  free(tt);
  Scalar_Multiplication(G, &R, key_mpz);

  public_key_uncompressed[0] = 0x04;
  count = 0;

	while(mpz_cmp(key_mpz,max_mpz) < 0 ) {
		mpz_set(temporal.x,R.x);
		mpz_set(temporal.y,R.y);
		//hexstrpoint
		gmp_sprintf(hexstrpoint,"%0.64Zx",R.x);
		hexs2bin(hexstrpoint,public_key_compressed+1);

		if(mpz_tstbit(R.y, 0) == 0)	{	// Even
			public_key_compressed[0] = 0x02;
		}
		else	{
			public_key_compressed[0] = 0x03;
		}
    if(FLAGMODE)  { // FLAGMODE == 1
      if( (FLAGCRYPTO & CRYPTO_BTC) != 0) {
				memcpy(public_key_uncompressed+1,public_key_compressed+1,32);
				gmp_sprintf(hexstrpoint,"%0.64Zx",R.y);
				hexs2bin(hexstrpoint,public_key_uncompressed+33);

        public_address_compressed = pubkeytopubaddress(public_key_compressed,33);
        public_address_uncompressed = pubkeytopubaddress(public_key_uncompressed,65);

        if(FLAGVANITY)  {
          if(strncmp(public_address_uncompressed,vanity,len_vanity) == 0)	{
            hextemp = malloc(65);
            mpz_get_str(hextemp,16,key_mpz);
            vanityKeys = fopen("vanitykeys.txt","a+");
            if(vanityKeys != NULL)	{
              fprintf(vanityKeys,"PrivKey: %s\n%s\n",hextemp,public_address_uncompressed);
              fclose(vanityKeys);
            }
            free(hextemp);
          }
          if(strncmp(public_address_compressed,vanity,len_vanity) == 0)	{
            hextemp = malloc(65);
            mpz_get_str(hextemp,16,key_mpz);
            vanityKeys = fopen("vanitykeys.txt","a+");
            if(vanityKeys != NULL)	{
              fprintf(vanityKeys,"PrivKey: %s\n%s\n",hextemp,public_address_compressed);
              fclose(vanityKeys);
            }
            free(hextemp);
          }
        }
        r = bloom_check(&bloom,public_address_compressed,MAXLENGTHADDRESS);
        if(r) {
          r = searchbinary(DATABUFFER,public_address_compressed,MAXLENGTHADDRESS,N);
          if(r) {
            hextemp = malloc(65);
            mpz_get_str(hextemp,16,key_mpz);
            public_key_compressed_hex = tohex(public_key_compressed,33);
            pthread_mutex_lock(&write_keys);
            keys = fopen("keys.txt","a+");
            if(keys != NULL)	{
              fprintf(keys,"PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_compressed_hex,public_address_compressed);
              fclose(keys);
            }
            printf("HIT!! PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_compressed_hex,public_address_compressed);
            pthread_mutex_unlock(&write_keys);
            free(public_key_compressed_hex);
            free(hextemp);
          }
        }
        r = bloom_check(&bloom,public_address_uncompressed,MAXLENGTHADDRESS);
        if(r) {
          r = searchbinary(DATABUFFER,public_address_uncompressed,MAXLENGTHADDRESS,N);
          if(r) {
            hextemp = malloc(65);
            mpz_get_str(hextemp,16,key_mpz);
            public_key_uncompressed_hex = tohex(public_key_uncompressed,65);
            pthread_mutex_lock(&write_keys);
            keys = fopen("keys.txt","a+");
            if(keys != NULL)	{
              fprintf(keys,"PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_uncompressed_hex,public_address_uncompressed);
              fclose(keys);
            }
            printf("HIT!! PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_uncompressed_hex,public_address_uncompressed);
            pthread_mutex_unlock(&write_keys);
            free(public_key_uncompressed_hex);
            free(hextemp);
          }
        }
        free(public_address_compressed);
        free(public_address_uncompressed);
      }
      if( ( FLAGCRYPTO & CRYPTO_ETH ) != 0) {
				/*
				mpz_export((public_key_uncompressed+1),&longtemp,1,8,1,0,R.x);
				mpz_export((public_key_uncompressed+33),&longtemp,1,8,1,0,R.y);
				public_address_uncompressed = pubkeytopubaddress_eth(public_key_uncompressed+1,64);
				//printf("Testing for %s\n",public_address_uncompressed);
				r = bloom_check(&bloom,public_address_uncompressed,MAXLENGTHADDRESS);
				if(r) {
					r = searchbinary(DATABUFFER,public_address_uncompressed,MAXLENGTHADDRESS,N);
					if(r) {
						hextemp = malloc(65);
						mpz_get_str(hextemp,16,key_mpz);
						public_key_uncompressed_hex = tohex(public_key_uncompressed+1,64);
						pthread_mutex_lock(&write_keys);
						keys = fopen("keys.txt","a+");
						if(keys != NULL)	{
							fprintf(keys,"PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_uncompressed_hex,public_address_uncompressed);
							fclose(keys);
						}
						printf("HIT!! PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_uncompressed_hex,public_address_uncompressed);
						pthread_mutex_unlock(&write_keys);
						free(public_key_uncompressed_hex);
						free(hextemp);
					}
					free(public_address_uncompressed);
				}
				*/
      }
    }
    else  { // FLAGMODE == 0
			/*
			public_key_compressed_hex = tohex(public_key_compressed+1,32);
			printf("Buscando %s\n",public_key_compressed_hex);
			free(public_key_compressed_hex);
			*/
			//printf("Checking: %s\n",hexstrpoint);
      r = bloom_check(&bloom,public_key_compressed+1,MAXLENGTHADDRESS);
  		if(r) {
  			r = searchbinary(DATABUFFER,public_key_compressed+1,MAXLENGTHADDRESS,N);
        if(r) {
					found++;
          hextemp = malloc(65);
          mpz_get_str(hextemp,16,key_mpz);
          public_key_compressed_hex = tohex(public_key_compressed,33);
  				pthread_mutex_lock(&write_keys);
  				keys = fopen("./keys.txt","a+");
  				if(keys != NULL)	{
  					fprintf(keys,"PrivKey: %s\npubkey: %s\n",hextemp,public_key_compressed_hex);
  					fclose(keys);
  				}
  				printf("HIT!! PrivKey: %s\npubkey: %s\n",hextemp,public_key_compressed_hex);
  				pthread_mutex_unlock(&write_keys);
          free(public_key_compressed_hex);
          free(hextemp);
        }
  		}
    }
		count++;
		if(count %  DEBUGCOUNT == 0)	{
      steps[thread_number]++;
		}
		mpz_add_ui(key_mpz,key_mpz,1);
		Point_Addition(&temporal,&G,&R);
	}
	printf("Testing Keys %lu\n",count);
	printf("Found %i\n",found);
  ends[thread_number] = 1;
}

void swap(char *a,char *b)  {
  char t[MAXLENGTHADDRESS];
  memcpy(t,a,MAXLENGTHADDRESS);
  memcpy(a,b,MAXLENGTHADDRESS);
  memcpy(b,t,MAXLENGTHADDRESS);
}

int partition (char *arr, int low, int high)  {
    char *pivot = arr + (high*MAXLENGTHADDRESS);    // pivot
		//printf("Pivot : %s\n",pivot);
    int j,i = (low - 1);  // Index of smaller element
    for (j = low; j < high; j++)  {
        // If current element is smaller than the pivot
        if (memcmp(arr + (j*MAXLENGTHADDRESS),pivot,MAXLENGTHADDRESS) < 0)  {
            i++;    // increment index of smaller element
            swap(arr + (i*MAXLENGTHADDRESS), arr + (j*MAXLENGTHADDRESS));
        }
    }
    swap(arr + ((i+1)*MAXLENGTHADDRESS), arr + (high*MAXLENGTHADDRESS));
    return (i + 1);
}

void quicksort(char *arr, int low, int high)  {
  int pi;
  if (low < high)  {
      pi = partition(arr, low, high);
      quicksort(arr, low, pi - 1);
      quicksort(arr, pi + 1, high);
  }
}
