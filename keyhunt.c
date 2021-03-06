
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
#include <math.h>
#include <time.h>
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"
#include "bloom/bloom.h"
#include "util.h"

#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define CRYPTO_ETH 2
#define CRYPTO_ALL 3

#define MODE_XPOINT 0
#define MODE_ADDRESS 1
#define MODE_BSGS 2

struct Point {
	mpz_t x;
	mpz_t y;
};

struct Elliptic_Curve {
	mpz_t p;
  mpz_t n;
};

struct bsgs_xvalue	{
	uint8_t value[8];
	int64_t index;
};

struct tothread {
  int nt; 		//Number thread
  char *rs; 	//range start
  char *rpt;  //rng per thread
};

const char *version = "0.1.20210306 K*BSGS";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
struct Point DoublingG[256];

void Point_Doubling(struct Point *P, struct Point *R);
void Point_Addition(struct Point *P, struct Point *Q, struct Point *R);
void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m);
void Point_Negation(struct Point *A, struct Point *S);
int searchbinary(char *BUFFER,char *data,int length,int _N);

void _sort(char *arr,int N);
void _insertionsort(char *arr, int n);
void _introsort(char *arr,int depthLimit, int n);
void swap(char *a,char *b);
int partition(char *arr, int n);
void myheapsort(char  *arr, int64_t n);
void heapify(char *arr, int n, int i);

void bsgs_sort(struct bsgs_xvalue *arr,int64_t n);
void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_introsort(struct bsgs_xvalue *arr,uint32_t depthLimit, int64_t n);
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b);
void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i);
int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n);


int bsgs_searchbinary(struct bsgs_xvalue *arr,char *data,int64_t _N,int64_t *r_value);

void *thread_process(void *vargp);
void *thread_process_range(void *vargp);
void *thread_process_bsgs(void *vargp);
void *thread_process_bsgs_random(void *vargp);

void init_doublingG(struct Point *P);
char *pubkeytopubaddress(char *pkey,int length);
//char *pubkeytopubaddress_eth(char *pkey,int length);


char *bit_range_str_min;
char *bit_range_str_max;

const char *modes[3] = {"xpoint","address","bsgs"};
const char *cryptos[3] = {"btc","eth","all"};
const char *default_filename = "addresses.txt";
const char *minus_params[2] = {"quiet","help"};

pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_range;
pthread_mutex_t write_random;
pthread_mutex_t threads_end;
pthread_mutex_t bsgs_thread;

struct Elliptic_Curve EC;
struct bloom bloom;
struct Point G;

unsigned int *steps = NULL;
unsigned int *ends = NULL;
char *DATABUFFER;
uint32_t N = 0;
gmp_randstate_t state;

uint64_t N_SECUENTIAL_MAX = 0xffffffff;
uint64_t DEBUGCOUNT = 0x100000;

int FLAGQUIET = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;
int OUTPUTSECONDS = 30;
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAGVANITY = 0;
int FLAGMODE = MODE_ADDRESS;
int FLAGCRYPTO = 0;
int FLAGALREADYSORTED = 0;
int FLAGRAWDATA  = 0;
int FLAGRANDOM = 0;
int FLAG_N = 0;
int FLAGPRECALCUTED_P_FILE = 0;
int FLAGPRECALCUTED_MP_FILE = 0;

int len_vanity;
int bitrange;
char *vanity;
char *range_start;
char *range_end;

uint64_t BSGS_XVALUE_RAM = 8;
uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;

/*
	BSGS Variables
*/
int *bsgs_found;
struct Point *OriginalPointsBSGS;
struct bsgs_xvalue *bPtable;
struct bloom bloom_bPx;
uint64_t bsgs_m;
unsigned long int bsgs_aux;
uint32_t bsgs_point_number;
mpz_t BSGS_CURRENT;
mpz_t BSGS_R;
mpz_t BSGS_AUX;
mpz_t BSGS_N;
mpz_t BSGS_M;							//M is squareroot(N)
mpz_t TWO;
mpz_t MPZAUX;
struct Point BSGS_P;			//Original P is actually G, but this P value change over time for calculations
struct Point BSGS_MP;			//MP values this is m * P
struct Point *BSGS_AMP;

struct Point point_temp,point_temp2;	//Temp value for some process

mpz_t n_range_start;
mpz_t n_range_end;
mpz_t n_range_diff;
mpz_t n_range_per_threads;
mpz_t n_range_aux;
mpz_t n_range_r;

int main(int argc, char **argv)	{
	char temporal[65];
	char rawvalue[32];
  struct tothread *tt;  //tothread
  Tokenizer t,tokenizerbsgs;  //tokenizer
  char *filename,*precalculated_p_filename,*precalculated_mp_filename;
	FILE *fd;
  char *hextemp,*aux,*aux2,*pointx_str,*pointy_str;
	uint64_t i;
	int64_t j;
	int readed,s,continue_flag,check_flag,r,lenaux,lendiff;
	mpz_t total;
	mpz_t pretotal;
	mpz_t debugcount_mpz;
	uint32_t seconds = 0;

  int c;
	gmp_randinit_mt(state);
	gmp_randseed_ui(state, ((int)clock()) + ((int)time(NULL)) );
	printf("[+] Version %s\n",version);
  mpz_init_set_str(EC.p, EC_constant_P, 16);
  mpz_init_set_str(EC.n, EC_constant_N, 16);
	mpz_init_set_str(G.x , EC_constant_Gx, 16);
	mpz_init_set_str(G.y , EC_constant_Gy, 16);
	init_doublingG(&G);
	mpz_init_set_ui(TWO,2);
	mpz_init(MPZAUX);

  while ((c = getopt(argc, argv, "ehqRwb:c:f:g:k:m:n:p:r:s:t:v:-:")) != -1) {
    switch(c) {
			case 'h':
        printf("\nUsage:\n-h\t\tshow this help\n");
				printf("-a file\t\tfile is a binary raw file with the aMP points precalculated. Just work with -m bsgs\n");
				printf("-b bits\t\tFor some puzzles you only need some numbers of bits in the test keys.\n");
				printf("\t\tThis option only is valid with the Random option -R\n");
				printf("-c crypto\tSearch for specific crypo. < btc, eth, all > valid only w/ -m address \n");
				printf("\t\teth option is under develop sorry :(\n");
				printf("-e\t\tThe file is already Sorted descendent. This skip the sorting process.\n");
				printf("\t\tYour file MUST be sordted if no you are going to lose collisions\n");
        printf("-f file\t\tSpecify filename with addresses or xpoints or uncompressed public keys\n");
				printf("-g count\tJust for the stats, mark as counted every debugcount keys	\n");
				printf("-k value\tUse this with bsgs mode, k value is factor for M, more speed but more RAM use wisely\n");
        printf("-m mode\t\tmode of search for cryptos. < address, xpoint, bsgs >  default: address (more slow)\n");
				printf("-n uptoN\tCheck for N secuential numbers before the random chossen this only work with -R option\n");
				printf("\t\tUse -n to set the N for the BSGS process. Bigger N more RAM needed\n");
				printf("-p file\t\tfile is a binary raw file with the bP points precalculated. Just work with -m bsgs\n");
				printf("-q\t\tset quiet the thread output\n");
        printf("-r SR:EN\tStarRange:EndRange, the end range can be omited for search from start range to N-1 ECC value\n");
				printf("-R\t\tRandom/Secuential this is the default behaivor, can't use this with range option -r\n");
        printf("-s ns\t\tNumber of seconds for the stats output, 0 to omit output.\n");
        printf("-t tn\t\tThreads number, must be positive integer\n");
				printf("-v va\t\tSearch for vanity Address, only with -m address\n");
				printf("-w\t\tMark the input file as RAW data xpoint fixed 32 byte each point. Valid only with -m xpoint\n");
				printf("\t\tUse the hexcharstoraw tool to create a raw file from your current hexadecimal file\n");
        printf("\nExample\n\n");
        printf("%s -t 16 -r 00000001:FFFFFFFF -s 0\n\n",argv[0]);
        printf("This line run the program with 16 threads from the range 00000001 to FFFFFFFF without stats output\n\n");
        printf("Developed by AlbertoBSD\tTips BTC: 1ABSD1rMTmNZHJrJP8AJhDNG1XbQjWcRz7\n");
				printf("Thanks to Iceland always helping and sharing his ideas, Tips to Iceland: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at\n\n");
        exit(0);
      break;
			case 'a':
				FLAGPRECALCUTED_MP_FILE = 1;
				precalculated_mp_filename = optarg;
			break;
			case 'b':
				bitrange = strtol(optarg,NULL,10);
				if(bitrange > 0 && bitrange <=256 )	{
					/*Buscar bit_range_str_min and bit_range_str_max*/

					mpz_pow_ui(MPZAUX,TWO,bitrange);
					bit_range_str_min = mpz_get_str(NULL,16,MPZAUX);
					mpz_pow_ui(MPZAUX,TWO,bitrange+1);
					bit_range_str_max = mpz_get_str(NULL,16,MPZAUX);
					if(bit_range_str_min == NULL||bit_range_str_max == NULL)	{
						fprintf(stderr,"[E] error malloc()\n");
						exit(0);
					}
					printf("[+] Min range: %s\n",bit_range_str_min);
					printf("[+] Max range: %s\n",bit_range_str_max);
					FLAGBITRANGE = 1;
				}
        else	{
					fprintf(stderr,"[E] invalid bits param: %s.\n",optarg);
				}
      break;
      case 'c':
        switch(indexOf(optarg,cryptos,3)) {
            case 0: //btc
              FLAGCRYPTO = CRYPTO_BTC;
              printf("[+] Setting search for btc adddress.\n");
            break;
            case 1: //eth
              FLAGCRYPTO = CRYPTO_ETH;
              printf("[+] Setting search for eth adddress.\n");
            break;
            case 2: //all
              FLAGCRYPTO = CRYPTO_ALL;
              printf("[+] Setting search for all cryptocurrencies avaible [btc].\n");
            break;
            default:
              FLAGCRYPTO = CRYPTO_NONE;
              fprintf(stderr,"[E] Unknow crypto value %s\n",optarg);
            break;
        }
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
					fprintf(stderr,"[E] invalid -g option value: %s.\n",optarg);
				}
      break;
			case 'k':
				KFACTOR = (int)strtol(optarg,NULL,10);
				if(KFACTOR <= 0)	{
					KFACTOR = 1;
				}
				printf("[+] Setting k factor to %i\n",KFACTOR);
			break;
      case 'm':
        switch(indexOf(optarg,modes,3)) {
          case MODE_XPOINT: //xpoint
            FLAGMODE = MODE_XPOINT;
            printf("[+] Setting mode xpoint\n");
          break;
          case MODE_ADDRESS: //address
            FLAGMODE = MODE_ADDRESS;
            printf("[+] Setting mode address\n");
          break;
					case MODE_BSGS:
						FLAGMODE = MODE_BSGS;
						printf("[+] Setting mode BSGS\n");
					break;
          default:
            FLAGMODE = MODE_ADDRESS;
            fprintf(stderr,"[+] Unknow mode value %s.\n",optarg);
          break;
        }
      break;
			case 'n':
				FLAG_N = 1;
				N_SECUENTIAL_MAX = strtol(optarg,NULL,10);
				if(N_SECUENTIAL_MAX <= 0)	{
					FLAG_N = 0;
					N_SECUENTIAL_MAX = 0xFFFFFFFF;
				}
			break;
			case 'q':
				FLAGQUIET  = 1;
				printf("[+] Set quiet thread output\n");
			break;
			case 'p':
				FLAGPRECALCUTED_P_FILE = 1;
				precalculated_p_filename = optarg;
			break;
			case 'R':
				FLAGRANDOM = 1;
				printf("[+] Setting random mode.\n");
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
                fprintf(stderr,"[E] Invalid hexstring : %s.\n",range_start);
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
                  printf("[E] Invalid hexstring : %s\n",range_start);
                }
                else  {
                  printf("[E] Invalid hexstring : %s\n",range_end);
                }
              }
            break;
            default:
              printf("[E] Unknow number of Range Params: %i\n",t.n);
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
          printf("[+] Turn off stats output\n");
        }
        else  {
          printf("[+] Stats output every %u seconds\n",OUTPUTSECONDS);
        }
      break;
			case 't':
        NTHREADS = strtol(optarg,NULL,10);
        if(NTHREADS <= 0)  {
          NTHREADS = 1;
        }
        printf((NTHREADS > 1) ? "[+] Setting %u threads\n": "[+] Setting %u thread\n",NTHREADS);
      break;
			case 'v':
        FLAGVANITY = 1;
        vanity = optarg;
        len_vanity = strlen(optarg);
				printf("[+] Added Vanity search : %s\n",vanity);
      break;
			case 'w':
			printf("[+] Data marked as RAW\n");
				FLAGRAWDATA = 1;
      break;
			case '-':
				switch(indexOf(optarg,minus_params,2))	{
					case 0:	//--quiet
						FLAGQUIET  = 1;
						printf("[+] Set quiet thread output\n");
					break;
					case 1:	// --help
					break;
					default:
						printf("[E] unknow param %s\n",optarg);
					break;
				}
			break;
      default:
        printf("[E] Unknow opcion %c\n",c);
      break;
    }
  }
	/*
	gmp_printf("[+] %Zu\n",EC.p);
	gmp_printf("[+] %Zu\n",EC.n);
	*/
	if(FLAGMODE != MODE_BSGS  && FLAGRANDOM == 1)	{
		FLAGRANGE = 0;
	}
	if(DEBUGCOUNT  > N_SECUENTIAL_MAX)	{
		DEBUGCOUNT = N_SECUENTIAL_MAX - 1;
		//printf("Setting debug count to %u",N_SECUENTIAL_MAX);
	}
	if(FLAGFILE == 0) {
		filename =(char*) default_filename;
	}
	printf("[+] Opening file %s\n",filename);
	fd = fopen(filename,"rb");
  if(fd == NULL)	{
    fprintf(stderr,"[E] Can't open file %s\n",filename);
    exit(0);
  }
  if(FLAGMODE == MODE_ADDRESS && FLAGCRYPTO == CRYPTO_NONE) {  //When none crypto is defined the default search is for Bitcoin
    FLAGCRYPTO = CRYPTO_BTC;
    printf("[+] Setting search for btc adddress\n");
  }
  if(FLAGRANGE) {
    mpz_init_set_str(n_range_start,range_start,16);
    mpz_init_set_str(n_range_end,range_end,16);
    if(mpz_cmp(n_range_start,n_range_end) != 0 ) {
      if(mpz_cmp(n_range_start,EC.n) < 0 && mpz_cmp(n_range_end,EC.n) <= 0)  {
        if(mpz_cmp(n_range_start,n_range_end) > 0) {
          fprintf(stderr,"[W] Opps, start and range can't be great than End range. Swapping them\n");
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
        fprintf(stderr,"[E] Start and End range can't be great than N\nFallback to random mode!\n");
        FLAGRANGE = 0;
      }
    }
    else  {
      fprintf(stderr,"[E] Start and End range can't be the same\nFallback to random mode!\n");
      FLAGRANGE = 0;
    }
  }
  N =0;
	if(FLAGMODE != MODE_BSGS)	{
		if(FLAGRAWDATA) {
			aux = malloc(32);
			if(aux == NULL)	{
				fprintf(stderr,"[E] error malloc()\n");
			}
			while(!feof(fd))  {
				if(fread(aux,1,32,fd) == 32)	{
					N++;
				}
			}
			free(aux);
		}
		else	{
		  aux = malloc(1000);
			if(aux == NULL)	{
				fprintf(stderr,"[E] error malloc()\n");
			}
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
		}
	  fseek(fd,0,SEEK_SET);
	  if(FLAGMODE == 0 || FLAGRAWDATA)  {
	    MAXLENGTHADDRESS = 32;
	  }

		printf("[+] Allocating memory for %u elements\n",N);
		i = 0;
	  do {
			DATABUFFER = malloc(MAXLENGTHADDRESS*N);
			i++;
		} while(DATABUFFER == NULL && i < 10);
		if(DATABUFFER == NULL)	{
			fprintf(stderr,"[E] Can't alloc memory for %u elements\n",N);
			exit(0);
		}
	  printf("[+] Initializing bloom filter for %u elements.\n",N);
		if(N <= 10000)	{
			if(bloom_init2(&bloom,10000,0.0001)  == 1){
				fprintf(stderr,"[E] error bloom_init for 10000 elements.\n");
				exit(0);
			}
		}
		else	{
			if(bloom_init2(&bloom,N,0.0001)  == 1){
				fprintf(stderr,"[E] error bloom_init for %u elements.\n",N);
				fprintf(stderr,"[+] man enough is enough stop it\n");
				exit(0);
			}
		}
	  printf("[+] Loading data to the bloomfilter\n");
		i = 0;
	  if(FLAGMODE == MODE_ADDRESS)  { //Address
			aux = malloc(2*MAXLENGTHADDRESS);
			if(aux == NULL)	{
				fprintf(stderr,"[E] error malloc()\n");
				exit(0);
			}
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
					fprintf(stderr,"[E] Omiting line : %s\n",aux);
				}
	    }
	  }
	  if(FLAGMODE == MODE_XPOINT)  {
			if(FLAGRAWDATA)	{
				aux = malloc(MAXLENGTHADDRESS);
				if(aux == NULL)	{
					fprintf(stderr,"[E] error malloc()\n");
					exit(0);
				}
				while(i < N)  {
					if(fread(aux,1,MAXLENGTHADDRESS,fd) == 32)	{
						memcpy(DATABUFFER + (i*MAXLENGTHADDRESS),aux,MAXLENGTHADDRESS);
						bloom_add(&bloom, aux,MAXLENGTHADDRESS);
					}
					i++;
				}
			}
			else	{
				aux = malloc(3*MAXLENGTHADDRESS);
				if(aux == NULL)	{
					fprintf(stderr,"[E] error malloc()\n");
					exit(0);
				}
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
								if(hexs2bin(aux,(unsigned char*)(DATABUFFER + (uint64_t)(i*MAXLENGTHADDRESS))))	{
										bloom_add(&bloom,(char*)( DATABUFFER + (uint64_t)(i*MAXLENGTHADDRESS)),MAXLENGTHADDRESS);
								}
								else	{
									fprintf(stderr,"[E] error hexs2bin\n");
								}
							}
							else	{
								fprintf(stderr,"[E] Omiting line : %s\n",aux);
							}
			      }
			      else  {
			        fprintf(stderr,"[E] Ignoring invalid hexvalue %s\n",aux);
			      }
			      i++;
					}
					else	{
						fprintf(stderr,"[E] Omiting line : %s\n",aux);
					}
		    }
			}
	  }
		free(aux);
	  fclose(fd);
		printf("[+] Bloomfilter completed\n");
		if(FLAGALREADYSORTED)	{
		  printf("[+] File mark already sorted, skipping sort proccess\n");
			printf("[+] %i values were loaded\n",N);
			_sort(DATABUFFER,N);
			_insertionsort(DATABUFFER,N);
		}
		else	{
			printf("[+] Sorting data\n");
			_sort(DATABUFFER,N);
			_insertionsort(DATABUFFER,N);
			printf("[+] %i values were loaded and sorted\n",N);
		}
	}
	if(FLAGMODE == MODE_BSGS)	{
		DEBUGCOUNT = N_SECUENTIAL_MAX ;
		aux = malloc(1024);
		if(aux == NULL)	{
			fprintf(stderr,"[E] error malloc()\n");
			exit(0);
		}
		while(!feof(fd))  {
			if(fgets(aux,1022,fd) == aux)	{
				trim(aux," \t\n\r");
				if(strlen(aux) >= 128)	{	//Length of a full address in hexadecimal without 04
						N++;
				}
			}
		}
		if(N == 0)	{
			fprintf(stderr,"[E] There is no valid data in the file\n");
			exit(0);
		}
		bsgs_found = calloc(N,sizeof(int));
		OriginalPointsBSGS = malloc(N*sizeof(struct Point));
		pointx_str = malloc(65);
		pointy_str = malloc(65);
		if(OriginalPointsBSGS == NULL || pointy_str == NULL || pointx_str == NULL || bsgs_found == NULL)	{
			fprintf(stderr,"[E] error malloc()\n");
			exit(0);
		}
		fseek(fd,0,SEEK_SET);
		i = 0;
		while(!feof(fd))  {
			if(fgets(aux,1022,fd) == aux)	{
				trim(aux," \t\n\r");
				if(strlen(aux) >= 128)	{
					stringtokenizer(aux,&tokenizerbsgs);
					aux2 = nextToken(&tokenizerbsgs);
					memset(pointx_str,0,65);
					memset(pointy_str,0,65);
					switch(strlen(aux2))	{
						case 128:	//Without the 04
							memcpy(pointx_str,aux2,64);
							memcpy(pointy_str,aux2+64,64);
							if(isValidHex(pointx_str) && isValidHex(pointy_str))	{
								mpz_init_set_str(OriginalPointsBSGS[i].x,pointx_str,16);
								mpz_init_set_str(OriginalPointsBSGS[i].y,pointy_str,16);
								//printf("Adding point ( %s , %s )\n",pointx_str,pointy_str);
								i++;
							}
							else	{
								fprintf(stderr,"[E] Some invalid hexdata in the file: %s\n",aux2);
								N--;
							}
						break;
						case 130:	//With the 04
							memcpy(pointx_str,aux2+2,64);
							memcpy(pointy_str,aux2+2+64,64);
							if(isValidHex(pointx_str) && isValidHex(pointy_str))	{
								mpz_init_set_str(OriginalPointsBSGS[i].x,pointx_str,16);
								mpz_init_set_str(OriginalPointsBSGS[i].y,pointy_str,16);
								//printf("Adding point ( %s , %s )\n",pointx_str,pointy_str);
								i++;
							}
							else	{
								fprintf(stderr,"[E] Some invalid hexdata in the file: %s\n",aux2);
								N--;
							}

						break;
						default:
							printf("Invalid length: %s\n",aux2);
							N--;
						break;
					}
					freetokenizer(&tokenizerbsgs);
				}
			}
		}
		fclose(fd);
		bsgs_point_number = N;
		printf("[+] Added %u points from file\n",bsgs_point_number);
		mpz_init(BSGS_N);
		mpz_init(BSGS_M);
		mpz_init(point_temp.x);
		mpz_init(point_temp.y);
		mpz_init(point_temp2.x);
		mpz_init(point_temp2.y);
		mpz_init_set_ui(BSGS_MP.x,0);
		mpz_init_set_ui(BSGS_MP.y,0);
		mpz_init_set(BSGS_P.x,G.x);
		mpz_init_set(BSGS_P.y,G.y);

		mpz_set_ui(BSGS_M,bsgs_m);

		if(FLAG_N)	{	//Custom N by the -n param
			memset(aux,0,100);
			sprintf(aux,"%llu",(long long unsigned int)N_SECUENTIAL_MAX);
			mpz_set_str(BSGS_N,aux,10);
		}
		else	{	//Default N
			mpz_set_str(BSGS_N,"100000000000",16);
		}
		if(!mpz_root(BSGS_M,BSGS_N,2))	{	//If the root wasn't exact
			mpz_add_ui(BSGS_M,BSGS_M,1);	//Add an extra integer, This is like a CEIL Funtion
		}
		bsgs_m = mpz_get_ui(BSGS_M);
		mpz_mul(BSGS_N,BSGS_M,BSGS_M);

		DEBUGCOUNT = (uint64_t)((uint64_t)bsgs_m * (uint64_t)bsgs_m);

		if(FLAGRANGE || FLAGBITRANGE)	{
			if(FLAGBITRANGE)	{	// Bit Range
				mpz_init_set_str(n_range_start,bit_range_str_min,16);
				mpz_init_set_str(n_range_end,bit_range_str_max,16);
				mpz_init(n_range_diff);
				mpz_sub(n_range_diff,n_range_end,n_range_start);

				printf("[+] Bit Range %i\n",bitrange);
			}
		}
		else	{

			mpz_init_set_ui(n_range_start,1);
			mpz_init_set(n_range_end,EC.n);

			mpz_urandomm(n_range_start,state,n_range_end);
			mpz_init(n_range_diff);
			mpz_sub(n_range_diff,n_range_end,n_range_start);
		}
		mpz_init_set(BSGS_CURRENT,n_range_start);

		if(mpz_cmp(n_range_diff,BSGS_N) < 0 )	{
			mpz_set(BSGS_N,n_range_diff);
			if(!mpz_root(BSGS_M,BSGS_N,2))	{	//If the root wasn't exact
				mpz_add_ui(BSGS_M,BSGS_M,1);	//Add an extra integer, This is CEIL Funtion
			}
			bsgs_m = mpz_get_ui(BSGS_M);
			mpz_mul(BSGS_N,BSGS_M,BSGS_M);
			DEBUGCOUNT = (uint64_t)((uint64_t)bsgs_m * (uint64_t)bsgs_m);
		}
		mpz_init(BSGS_R);
		mpz_init(BSGS_AUX);
		mpz_mul_ui(BSGS_M,BSGS_M,KFACTOR);
		mpz_cdiv_q(BSGS_AUX,BSGS_N,BSGS_M);
		mpz_cdiv_r(BSGS_R,BSGS_N,BSGS_M);
		if(mpz_cmp_ui(BSGS_R,0) != 0 ) {
			mpz_mul(BSGS_N,BSGS_M,BSGS_AUX);
		}
		bsgs_m = (uint64_t)((uint64_t) bsgs_m * (uint64_t)KFACTOR);
		bsgs_aux = mpz_get_ui(BSGS_AUX);
		DEBUGCOUNT = (uint64_t)((uint64_t)bsgs_m * (uint64_t)bsgs_aux);

		printf("[+] Setting N up to %llu.\n",(long long unsigned int)DEBUGCOUNT);
		if(bsgs_m > 1000)	{
			if(bloom_init2(&bloom_bPx,bsgs_m,0.001)  == 1){
				fprintf(stderr,"[E] error bloom_init for %lu elements\n",bsgs_m);
				exit(0);
			}
		}
		else	{
			if(bloom_init2(&bloom_bPx,1000,0.001)  == 1){
				fprintf(stderr,"[E] error bloom_init for 1000 elements\n");
				exit(0);
			}
		}
		printf("[+] Init bloom filter for %lu elements : %.2f MB\n",bsgs_m,(float)((uint64_t)bloom_bPx.bytes/(uint64_t)1048576));

		//gmp_printf("BSGS_M: %0.64Zx\n",BSGS_M);


		Scalar_Multiplication(G,&BSGS_MP,BSGS_M);

		printf("[+] Allocating %.2f MB for aMP Points\n",(float)(((uint64_t)(bsgs_aux*sizeof(struct Point)))/(uint64_t)1048576));
		i = 0;
		do {
			BSGS_AMP = malloc((uint64_t)((uint64_t)bsgs_aux*(uint64_t)sizeof(struct Point)));
			i++;
			if(BSGS_AMP == NULL)	{
				sleep(1);
			}
		} while( i <= 10 && BSGS_AMP == NULL);

		if(BSGS_AMP == NULL)	{
			printf("[E] error malloc()\n");
			exit(0);
		}
		i= 0;
		if(FLAGPRECALCUTED_MP_FILE)	{
			printf("[+] Reading aMP points from file %s\n",precalculated_mp_filename);
			fd = fopen(precalculated_mp_filename,"rb");
			if(fd != NULL)	{
				while(!feof(fd) && i < bsgs_aux )	{
					if(fread(temporal,1,64,fd) == 64)	{
						hextemp = tohex(temporal,32);
						mpz_init_set_str(BSGS_AMP[i].x,hextemp,16);
						free(hextemp);
						hextemp = tohex(temporal+32,32);
						mpz_init_set_str(BSGS_AMP[i].y,hextemp,16);
						free(hextemp);
						i++;
					}
				}
				if(i < bsgs_aux)	{	//If the input file have less item than bsgs_m
					printf("[+] Fixme file contains less items than the amount of items needed\n");
					exit(0);
				}
			}
			else	{
				fprintf(stderr,"[E] Can't open file %s falling back to the calculation mode\n",filename);
				printf("[+] Precalculating %lu aMP points\n",bsgs_aux);
				mpz_set(point_temp.x,BSGS_MP.x);
				mpz_set(point_temp.y,BSGS_MP.y);
				for(i = 0; i < bsgs_aux; i++)	{
					mpz_init(BSGS_AMP[i].x);
					mpz_init(BSGS_AMP[i].y);
					Point_Negation(&point_temp,&BSGS_AMP[i]);
					Point_Addition(&point_temp,&BSGS_MP,&point_temp2);
					mpz_set(point_temp.x,point_temp2.x);
					mpz_set(point_temp.y,point_temp2.y);
				}
			}
		}
		else	{
			printf("[+] Precalculating %lu aMP points\n",bsgs_aux);
			mpz_set(point_temp.x,BSGS_MP.x);
			mpz_set(point_temp.y,BSGS_MP.y);
			for(i = 0; i < bsgs_aux; i++)	{
				mpz_init(BSGS_AMP[i].x);
				mpz_init(BSGS_AMP[i].y);
				Point_Negation(&point_temp,&BSGS_AMP[i]);
				Point_Addition(&point_temp,&BSGS_MP,&point_temp2);
				mpz_set(point_temp.x,point_temp2.x);
				mpz_set(point_temp.y,point_temp2.y);
			}
		}
		printf("[+] Allocating %.2f MB for bP Points\n",(float)((uint64_t)((uint64_t)bsgs_m*(uint64_t)sizeof(struct bsgs_xvalue))/(uint64_t)1048576));
		bPtable = calloc(bsgs_m,sizeof(struct bsgs_xvalue));
		if(bPtable == NULL)	{
			printf("[E] error malloc()\n");
			exit(0);
		}
		i = 0;
		j = 0;
		if(FLAGPRECALCUTED_P_FILE)	{
			printf("[+] Reading %lu bP points from file %s\n",bsgs_m,precalculated_p_filename);
			fd = fopen(precalculated_p_filename,"rb");
			if(fd != NULL)	{
				while(!feof(fd) && i < bsgs_m )	{
					if(fread(rawvalue,1,32,fd) == 32)	{
						//memcpy(bPtable[i].value,rawvalue,BSGS_XVALUE_RAM);
						bPtable[i].value[0] = rawvalue[6];
						bPtable[i].value[1] = rawvalue[7];
						bPtable[i].value[2] = rawvalue[14];
						bPtable[i].value[3] = rawvalue[15];
						bPtable[i].value[4] = rawvalue[22];
						bPtable[i].value[5] = rawvalue[23];
						bPtable[i].value[6] = rawvalue[30];
						bPtable[i].value[7] = rawvalue[31];

						bPtable[i].index = j;
						bloom_add(&bloom_bPx, rawvalue, BSGS_BUFFERXPOINTLENGTH);
						i++;
						j++;
					}
				}
				if(i < bsgs_m)	{	//If the input file have less item than bsgs_m
					printf("[+] Fixme, file contains less items than the amount of items needed\n");
					exit(0);
				}
			}
			else	{
				fprintf(stderr,"[E] Can't open file %s falling back to the calculation mode\n",precalculated_p_filename);
				printf("[+] Precalculating %lu bP points\n",bsgs_m);
				do {
					mpz_set(point_temp.x,BSGS_P.x);
					mpz_set(point_temp.y,BSGS_P.y);
					gmp_sprintf(temporal,"%0.64Zx",BSGS_P.x);
					hexs2bin(temporal,rawvalue);
					//memcpy(bPtable[i].value,rawvalue,4);
					bPtable[i].value[0] = rawvalue[6];
					bPtable[i].value[1] = rawvalue[7];
					bPtable[i].value[2] = rawvalue[14];
					bPtable[i].value[3] = rawvalue[15];
					bPtable[i].value[4] = rawvalue[22];
					bPtable[i].value[5] = rawvalue[23];
					bPtable[i].value[6] = rawvalue[30];
					bPtable[i].value[7] = rawvalue[31];

					bPtable[i].index = j;
					bloom_add(&bloom_bPx, rawvalue,BSGS_BUFFERXPOINTLENGTH);
					Point_Addition(&G,&point_temp,&BSGS_P);
					i++;
					j++;
				} while( i < bsgs_m );
			}
		}
		else	{
			printf("[+] precalculating %lu bP points\n",bsgs_m);
			do {
				mpz_set(point_temp.x,BSGS_P.x);
				mpz_set(point_temp.y,BSGS_P.y);
				gmp_sprintf(temporal,"%0.64Zx",BSGS_P.x);
				hexs2bin(temporal, rawvalue );
				//memcpy(bPtable[i].value,rawvalue,BSGS_XVALUE_RAM);
				bPtable[i].value[0] = rawvalue[6];
				bPtable[i].value[1] = rawvalue[7];
				bPtable[i].value[2] = rawvalue[14];
				bPtable[i].value[3] = rawvalue[15];
				bPtable[i].value[4] = rawvalue[22];
				bPtable[i].value[5] = rawvalue[23];
				bPtable[i].value[6] = rawvalue[30];
				bPtable[i].value[7] = rawvalue[31];
				bPtable[i].index = j;
				bloom_add(&bloom_bPx, rawvalue ,BSGS_BUFFERXPOINTLENGTH);
				Point_Addition(&G,&point_temp,&BSGS_P);
				i++;
				j++;
			} while( i < bsgs_m );
		}
		printf("[+] Sorting %lu elements\n",bsgs_m);
		bsgs_sort(bPtable,bsgs_m);
		i = 0;

		steps = (unsigned int *) calloc(NTHREADS,sizeof(int));
	  ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
		tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
		DEBUGCOUNT = (uint64_t)((uint64_t)bsgs_m * (uint64_t)bsgs_aux);
		//DEBUGCOUNT = (uint64_t)((uint64_t)bsgs_m * (uint64_t)bsgs_m);
		for(i= 0;i < NTHREADS; i++)  {
			tt = malloc(sizeof(struct tothread));
			tt->nt = i;
			if(FLAGRANDOM)	{
				s = pthread_create(&tid[i],NULL,thread_process_bsgs_random,(void *)tt);
			}
			else	{
				s = pthread_create(&tid[i],NULL,thread_process_bsgs,(void *)tt);
			}

			if(s != 0)  {
				fprintf(stderr,"[E] pthread_create thread_process\n");
				exit(0);
			}
		}
		free(aux);
	}
	if(FLAGMODE != MODE_BSGS)	{
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
	  			fprintf(stderr,"[E] pthread_create thread_process\n");
					exit(0);
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
	  			fprintf(stderr,"[E] pthread_create thread_process\n");
					exit(0);
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
	}
  continue_flag = 1;
	mpz_init(total);
	mpz_init(pretotal);
	mpz_init(debugcount_mpz);
	sprintf(temporal,"%llu",(long long unsigned int)DEBUGCOUNT);
	mpz_set_str(debugcount_mpz,temporal,10);
	printf("DEBUGCOUNT: %llu\n",DEBUGCOUNT);
	gmp_printf("debugcount_mpz: %Zu\n",debugcount_mpz);
	printf("NTHREADS: %i\n",NTHREADS);
  do  {
    sleep(1);
    seconds+=1;
    if(FLAGMODE != MODE_BSGS  && FLAGRANGE) {
      check_flag = 1;
			pthread_mutex_lock(&threads_end);
      for(i = 0; i <NTHREADS && check_flag; i++) {
        check_flag &= ends[i];
      }
			pthread_mutex_unlock(&threads_end);
      if(check_flag)  {
        continue_flag = 0;
      }
    }
    if(OUTPUTSECONDS > 0){
      if(seconds % OUTPUTSECONDS == 0) {
				mpz_set_ui(total,0);
				mpz_set_ui(pretotal,0);
        i = 0;
        while(i < NTHREADS) {
					mpz_mul_ui(pretotal,debugcount_mpz,steps[i]);
					/*printf("steps: %i\n",steps[i]);*/
					mpz_add(total,total,pretotal);
          i++;
        }
				if(mpz_cmp_ui(total,0) > 0)	{
					mpz_fdiv_q_ui(pretotal,total,seconds);
					pthread_mutex_lock(&bsgs_thread);
					gmp_printf("Total %Zu keys in %llu seconds: %Zu keys/s\n",total,seconds,pretotal);
					pthread_mutex_unlock(&bsgs_thread);
				}
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


/*
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
*/

/*
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
		if(mpz_cmp_ui(Q->x, 0) == 0 && mpz_cmp_ui(Q->y, 0) == 0) {
			mpz_set(R->x, P->x);
			mpz_set(R->y, P->y);
		}
		else	{
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
		}
	}
	mpz_clear(PA_temp);
	mpz_clear(PA_slope);
}
*/

void Point_Addition(struct Point *P, struct Point *Q, struct Point *R)	{
	mpz_t PA_temp,PA_slope;
	mpz_init(PA_temp);
	mpz_init(PA_slope);
	/*
	mpz_mod(Q->x, Q->x, EC.p);
	mpz_mod(Q->y, Q->y, EC.p);
	mpz_mod(P->x, P->x, EC.p);
	mpz_mod(P->y, P->y, EC.p);
	*/
	if(mpz_cmp_ui(P->x, 0) == 0 && mpz_cmp_ui(P->y, 0) == 0) {
		mpz_set(R->x, Q->x);
		mpz_set(R->y, Q->y);
	}
	else	{
		if(mpz_cmp_ui(Q->x, 0) == 0 && mpz_cmp_ui(Q->y, 0) == 0) {
			mpz_set(R->x, P->x);
			mpz_set(R->y, P->y);
		}
		else	{
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
					mpz_sub(PA_temp, P->x, Q->x);	//dx = B.x - A.x
					mpz_mod(PA_temp, PA_temp, EC.p);		///dx = dx % p
					mpz_invert(PA_temp, PA_temp, EC.p);	//gmpy2.invert(dx, p) % p
					mpz_sub(PA_slope, P->y, Q->y);
					mpz_mul(PA_slope, PA_slope, PA_temp);
					mpz_mod(PA_slope, PA_slope, EC.p);
					mpz_mul(R->x, PA_slope, PA_slope);	//c*c
					mpz_sub(R->x, R->x, P->x);	//	c*c - A.x
					mpz_sub(R->x, R->x, Q->x);	//(c*c - A.x) -  B.x
					mpz_mod(R->x, R->x, EC.p);	// Rx % p
					mpz_sub(PA_temp, P->x, R->x);
					mpz_mul(R->y, PA_slope, PA_temp);
					mpz_sub(R->y, R->y, P->y);
					mpz_mod(R->y, R->y, EC.p);
				}
			}
		}
	}
	mpz_clear(PA_temp);
	mpz_clear(PA_slope);
}

void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m)	{
	struct Point SM_T,SM_Q;
	int no_of_bits, i;
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

/*
char *pubkeytopubaddress_eth(char *pkey,int length)	{
		char *temp,*pubaddress = calloc(MAXLENGTHADDRESS,1);
		char *digest = malloc(32);
		if(digest == NULL || pubaddress == NULL)	{
			fprintf(stderr,"error malloc()\n");
			exit(0);
		}
		pubaddress[0] = '0';
		pubaddress[1] = 'x';
		shake256(digest, 256,(const uint8_t* ) pkey, length);
		temp = tohex(digest+12,20);
		strcpy(pubaddress+2,temp);
		free(temp);
		free(digest);
		return pubaddress;
}
*/

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
	RMD160Data((const unsigned char*)digest,32, digest+1);
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

int searchbinary(char *buffer,char *data,int length,int _N) {
	char *temp_read;
  int r = 0,rcmp,current_offset,half,min,max,current;
  min = 0;
  current = 0;
  max = _N;
  half = _N;
  while(!r && half >= 1) {
    half = (max - min)/2;
		temp_read = buffer + ((current+half) * length);
    rcmp = memcmp(data,temp_read,length);
    if(rcmp == 0)  {
      r = 1;  //Found!!
    }
    else  {
      if(rcmp < 0) { //data < temp_read
        max = (max-half);
      }
      else  { // data > temp_read
        min = (min+half);
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
	int r,thread_number,found;
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
		mpz_init_set_str(mpz_bit_range_min,bit_range_str_min,16);
		mpz_init_set_str(mpz_bit_range_max,bit_range_str_max,16);
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
	found = 0;
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
		gmp_sprintf(hextemp,"%0.64Zx",random_key_mpz);
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
			hexs2bin(hexstrpoint,(unsigned char*)(public_key_compressed+1));

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
					hexs2bin(hexstrpoint,(unsigned char*)(public_key_uncompressed+33));

          public_address_compressed = pubkeytopubaddress(public_key_compressed,33);
          public_address_uncompressed = pubkeytopubaddress(public_key_uncompressed,65);

          if(FLAGVANITY)  {
            if(strncmp(public_address_uncompressed,vanity,len_vanity) == 0)	{
              hextemp = malloc(65);
							gmp_sprintf(hextemp,"%0.64Zx",random_key_mpz);
      				vanityKeys = fopen("vanitykeys.txt","a+");
      				if(vanityKeys != NULL)	{
      					fprintf(vanityKeys,"PrivKey: %s\nAddress uncompressed: %s\n",hextemp,public_address_uncompressed);
      					fclose(vanityKeys);
      				}
							printf("Vanity privKey: %s\nAddress uncompressed:  %s\n",hextemp,public_address_uncompressed);
              free(hextemp);
      			}
            if(strncmp(public_address_compressed,vanity,len_vanity) == 0)	{
              hextemp = malloc(65);
              gmp_sprintf(hextemp,"%0.64Zx",random_key_mpz);
      				vanityKeys = fopen("vanitykeys.txt","a+");
      				if(vanityKeys != NULL)	{
      					fprintf(vanityKeys,"PrivKey: %s\nAddress compressed:  %s\n",hextemp,public_address_compressed);
      					fclose(vanityKeys);
      				}
							printf("Vanity privKey: %s\nAddress compressed: %s\n",hextemp,public_address_compressed);
              free(hextemp);
      			}
          }
          r = bloom_check(&bloom,public_address_compressed,MAXLENGTHADDRESS);
    			if(r) {
    				r = searchbinary(DATABUFFER,public_address_compressed,MAXLENGTHADDRESS,N);
    	      if(r) {
							found++;
              hextemp = malloc(65);
              gmp_sprintf(hextemp,"%0.64Zx",random_key_mpz);
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
							found++;
              hextemp = malloc(65);
              gmp_sprintf(hextemp,"%0.64Zx",random_key_mpz);
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
						found++;
            hextemp = malloc(65);
            gmp_sprintf(hextemp,"%0.64Zx",random_key_mpz);
            public_key_compressed_hex = tohex(public_key_compressed,33);
  					pthread_mutex_lock(&write_keys);
  					keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
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
	printf("Found %i\n",found);
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

	while(mpz_cmp(key_mpz,max_mpz) <= 0 ) {
		mpz_set(temporal.x,R.x);
		mpz_set(temporal.y,R.y);
		//hexstrpoint
		gmp_sprintf(hexstrpoint,"%0.64Zx",R.x);
		hexs2bin(hexstrpoint,(unsigned char*)(public_key_compressed+1));

		if(mpz_tstbit(R.y, 0) == 0)	{	// EVEN
			public_key_compressed[0] = 0x02;
		}
		else	{ //ODD
			public_key_compressed[0] = 0x03;
		}
    if(FLAGMODE)  { // FLAGMODE == 1
      if( (FLAGCRYPTO & CRYPTO_BTC) != 0) {
				memcpy(public_key_uncompressed+1,public_key_compressed+1,32);
				gmp_sprintf(hexstrpoint,"%0.64Zx",R.y);
				hexs2bin(hexstrpoint,(unsigned char*)(public_key_uncompressed+33));

        public_address_compressed = pubkeytopubaddress(public_key_compressed,33);
        public_address_uncompressed = pubkeytopubaddress(public_key_uncompressed,65);
				/*
				printf("Testing: %s\n",public_address_compressed);
				printf("Testing: %s\n",public_address_uncompressed);
				*/
        if(FLAGVANITY)  {
          if(strncmp(public_address_uncompressed,vanity,len_vanity) == 0)	{
            hextemp = malloc(65);
						gmp_sprintf(hextemp,"%0.64Zx",key_mpz);
            vanityKeys = fopen("vanitykeys.txt","a+");
            if(vanityKeys != NULL)	{
              fprintf(vanityKeys,"PrivKey: %s\nAddress uncompressed: %s\n",hextemp,public_address_uncompressed);
              fclose(vanityKeys);
            }
						printf("Vanity privKey: %s\nAddress uncompressed: %s\n",hextemp,public_address_uncompressed);
            free(hextemp);
          }
          if(strncmp(public_address_compressed,vanity,len_vanity) == 0)	{
						hextemp = malloc(65);
            gmp_sprintf(hextemp,"%0.64Zx",key_mpz);
            vanityKeys = fopen("vanitykeys.txt","a+");
            if(vanityKeys != NULL)	{
              fprintf(vanityKeys,"PrivKey: %s\nAddress compressed: %s\n",hextemp,public_address_compressed);
              fclose(vanityKeys);
            }
						printf("Vanity privKey: %s\nAddress compressed: %s\n",hextemp,public_address_compressed);
            free(hextemp);
          }
        }
        r = bloom_check(&bloom,public_address_compressed,MAXLENGTHADDRESS);
        if(r) {
					//printf("bloom_check: %i  for %s\n",r,public_address_compressed);
          r = searchbinary(DATABUFFER,public_address_compressed,MAXLENGTHADDRESS,N);
          if(r) {
						found++;
            hextemp = malloc(65);
						gmp_sprintf(hextemp,"%0.64Zx",key_mpz);
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
					//printf("bloom_check: %i  for %s\n",r,public_address_uncompressed);
          r = searchbinary(DATABUFFER,public_address_uncompressed,MAXLENGTHADDRESS,N);
          if(r) {
						found++;
            hextemp = malloc(65);
						gmp_sprintf(hextemp,"%0.64Zx",key_mpz);
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
          gmp_sprintf(hextemp,"%0.64Zx",key_mpz);
          public_key_compressed_hex = tohex(public_key_compressed,33);
  				pthread_mutex_lock(&write_keys);
  				keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
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

void _sort(char *arr,int n)  {
  int depthLimit = ((int) ceil(log(n))) * 2;
  _introsort(arr,depthLimit,n);
}

void _introsort(char *arr,int depthLimit, int n) {
  int p;
  if(n > 1)  {
    if(n <= 16) {
      _insertionsort(arr,n);
    }
    else  {
      if(depthLimit == 0) {
        myheapsort(arr,n);
      }
      else  {
        p = partition(arr,n);
        if(p >= 2) {
          _introsort(arr , depthLimit-1 , p);
        }
        if((n - (p + 1)) >= 2 ) {
          _introsort(arr + ((p+1) *MAXLENGTHADDRESS) , depthLimit-1 , n - (p + 1));
        }
      }
    }
  }
}

void _insertionsort(char *arr, int n) {
	int j,i;
  char *arrj,*temp;
  char key[MAXLENGTHADDRESS];
  for(i = 1; i < n ; i++ ) {
    j= i-1;
    memcpy(key,arr + (i*MAXLENGTHADDRESS),MAXLENGTHADDRESS);
    arrj = arr + (j*MAXLENGTHADDRESS);
    while(j >= 0 && memcmp(arrj,key,MAXLENGTHADDRESS) > 0) {
      memcpy(arr + ((j+1)*MAXLENGTHADDRESS),arrj,MAXLENGTHADDRESS);
      j--;
			if(j >= 0)	{
      	arrj = arr + (j*MAXLENGTHADDRESS);
			}
    }
    memcpy(arr + ((j+1)*MAXLENGTHADDRESS),key,MAXLENGTHADDRESS);
  }
}

int partition(char *arr, int n)  {
  char pivot[MAXLENGTHADDRESS];
  int j,i,t, r = (int) n/2,jaux = -1,iaux = -1, iflag, jflag;
  char *a,*b,*hextemp,*hextemp_pivot;
  i = - 1;
  memcpy(pivot,arr + (r*MAXLENGTHADDRESS),MAXLENGTHADDRESS);
  i = 0;
  j = n-1;
  do {
    iflag = 1;
    jflag = 1;
    t = memcmp(arr + (i*MAXLENGTHADDRESS),pivot,MAXLENGTHADDRESS);
    iflag = (t <= 0);
    while(i < j && iflag) {
      i++;
      t = memcmp(arr + (i*MAXLENGTHADDRESS),pivot,MAXLENGTHADDRESS);
      iflag = (t <= 0);
    }
    t = memcmp(arr + (j*MAXLENGTHADDRESS),pivot,MAXLENGTHADDRESS);
    jflag = (t > 0);
    while(i < j && jflag) {
      j--;
      t = memcmp(arr + (j*MAXLENGTHADDRESS),pivot,MAXLENGTHADDRESS);
      jflag = (t > 0);
    }
    if(i < j) {
      if(i == r )  {
        r = j;
      }
      else  {
        if(j == r )  {
          r = i;
        }
      }

      swap(arr + (i*MAXLENGTHADDRESS),arr + (j*MAXLENGTHADDRESS) );
      jaux = j;
      iaux = i;
      j--;
      i++;
    }

  } while(j > i );
  if(jaux != -1 && iaux != -1)  {
    if(iflag || jflag)  {
      if(iflag) {
        if(r != j)
          swap(arr + (r*MAXLENGTHADDRESS),arr + ((j )*MAXLENGTHADDRESS) );
        jaux = j;
      }
      if(jflag) {
        if(r != j-1)
          swap(arr + (r*MAXLENGTHADDRESS),arr + ((j-1 )*MAXLENGTHADDRESS) );
        jaux = j-1;
      }
    }
    else{
      if(r != j)
        swap(arr + (r*MAXLENGTHADDRESS),arr + ((j )*MAXLENGTHADDRESS) );
      jaux = j;
    }
  }
  else  {
    if(iflag && jflag)  {
      jaux = r;
    }
    else  {
      if(iflag ) {
        swap(arr + (r*MAXLENGTHADDRESS),arr + ((j)*MAXLENGTHADDRESS) );
        jaux = j;
      }
    }
  }
  return jaux;
}

void heapify(char *arr, int n, int i) {
    int largest = i;
    int l = 2 * i + 1;
    int r = 2 * i + 2;
    if (l < n && memcmp(arr +(l*MAXLENGTHADDRESS),arr +(largest * MAXLENGTHADDRESS),MAXLENGTHADDRESS) > 0)
        largest = l;
    if (r < n && memcmp(arr +(r*MAXLENGTHADDRESS),arr +(largest *MAXLENGTHADDRESS),MAXLENGTHADDRESS) > 0)
        largest = r;
    if (largest != i) {
        swap(arr +(i*MAXLENGTHADDRESS), arr +(largest*MAXLENGTHADDRESS));
        heapify(arr, n, largest);
    }
}

void myheapsort(char  *arr, int64_t n)  {
  int64_t i;
  for ( i = n / 2 - 1; i >= 0; i--)
    heapify(arr, n, i);
  for ( i = n - 1; i > 0; i--) {
    swap(arr , arr +(i*MAXLENGTHADDRESS));
    heapify(arr, i, 0);
  }
}

/*	OK	*/
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b)  {
	struct bsgs_xvalue t;
	t  = *a;
	*a = *b;
	*b =  t;
}

/*	OK	*/
void bsgs_sort(struct bsgs_xvalue *arr,int64_t n)  {
  uint32_t depthLimit = ((uint32_t) ceil(log(n))) * 2;
  bsgs_introsort(arr,depthLimit,n);
}

/*	OK	*/
void bsgs_introsort(struct bsgs_xvalue *arr,uint32_t depthLimit, int64_t n) {
  int64_t p;
  if(n > 1)  {
    if(n <= 16) {
      bsgs_insertionsort(arr,n);
    }
    else  {
      if(depthLimit == 0) {
        bsgs_myheapsort(arr,n);
      }
      else  {
        p = bsgs_partition(arr,n);
				if(p > 0) bsgs_introsort(arr , depthLimit-1 , p);
				if(p < n) bsgs_introsort(&arr[p+1],depthLimit-1,n-(p+1));
      }
  	}
  }
}

/*	OK	*/
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n) {
	int64_t j;
	int64_t i;
	struct bsgs_xvalue key;
  for(i = 1; i < n ; i++ ) {
		key = arr[i];
    j= i-1;
    while(j >= 0 && memcmp(arr[j].value,key.value,BSGS_XVALUE_RAM) > 0) {
			arr[j+1] = arr[j];
      j--;
    }
		arr[j+1] = key;
  }
}

int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n)  {
	struct bsgs_xvalue pivot;
	int64_t r,left,right;
	char *hextemp;
	r = n/2;
	pivot = arr[r];
	left = 0;
	right = n-1;
	do {
		while(left  < right && memcmp(arr[left].value,pivot.value,BSGS_XVALUE_RAM) <= 0 )	{
			left++;
		}
		while(right >= left && memcmp(arr[right].value,pivot.value,BSGS_XVALUE_RAM) > 0)	{
			right--;
		}
		if(left < right)	{
			if(left == r || right == r)	{
				if(left == r)	{
					r = right;
				}
				if(right == r)	{
					r = left;
				}
			}
			bsgs_swap(&arr[right],&arr[left]);
		}
	}while(left < right);
	if(right != r)	{
		bsgs_swap(&arr[right],&arr[r]);
	}
	return right;
}

void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i) {
  int64_t largest = i;
  int64_t l = 2 * i + 1;
  int64_t r = 2 * i + 2;
  if (l < n && memcmp(arr[l].value,arr[largest].value,BSGS_XVALUE_RAM) > 0)
    largest = l;
  if (r < n && memcmp(arr[r].value,arr[largest].value,BSGS_XVALUE_RAM) > 0)
    largest = r;
  if (largest != i) {
    bsgs_swap(&arr[i],&arr[largest]);
    bsgs_heapify(arr, n, largest);
  }
}

void bsgs_myheapsort(struct bsgs_xvalue  *arr, int64_t n)  {
  int64_t i;
  for ( i = (n / 2) - 1; i >=  0; i--)	{
    bsgs_heapify(arr, n, i);
	}
  for ( i = n - 1; i > 0; i--) {
    bsgs_swap(&arr[0] , &arr[i]);
    bsgs_heapify(arr, i, 0);
  }
}


int bsgs_searchbinary(struct bsgs_xvalue *buffer,char *data,int64_t _N,int64_t *r_value) {
	char *temp_read;
	int64_t min,max,half,current;
  int r = 0,rcmp;
  min = 0;
  current = 0;
  max = _N;
  half = _N;
  while(!r && half >= 1) {
    half = (max - min)/2;
    rcmp = memcmp(data,buffer[current+half].value,BSGS_XVALUE_RAM);
    if(rcmp == 0)  {
			*r_value = buffer[current+half].index;
			r = 1;
    }
    else  {
      if(rcmp < 0) {
        max = (max-half);
      }
      else  {
        min = (min+half);
      }
			current = min;
    }
  }
  return r;
}

void *thread_process_bsgs(void *vargp)	{
	struct tothread *tt;
	char pubkey[131],xpoint_str[65],xpoint_raw[32],tosearch[BSGS_XVALUE_RAM];
	char *aux_c;
	mpz_t base_key,keyfound;
	FILE *filekey;
	struct Point base_point,point_aux,point_aux2,point_found;
	struct Point *BSGS_Q, *BSGS_S,BSGS_Q_AMP;
	int64_t j;
	uint32_t i,k,r,salir,thread_number;
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	mpz_init(base_key);
	mpz_init(keyfound);
	mpz_init(base_point.x);
	mpz_init(base_point.y);
	mpz_init(point_aux.x);
	mpz_init(point_aux.y);
	mpz_init(point_aux2.x);
	mpz_init(point_aux2.y);
	mpz_init(point_found.x);
	mpz_init(point_found.y);
	mpz_init(BSGS_Q_AMP.x);
	mpz_init(BSGS_Q_AMP.y);

	BSGS_S = malloc(bsgs_point_number*sizeof(struct Point));
	BSGS_Q = malloc(bsgs_point_number*sizeof(struct Point));
	if(BSGS_Q == NULL || BSGS_S == NULL /*|| BSGS_AMP == NULL*/)	{
		fprintf(stderr,"[E] error malloc(): thread_process_bsgs\n");
		exit(0);
	}

	/* We initializing all BSGS_Q values this is GMP related stuff*/
	for(k = 0; k < bsgs_point_number; k++)	{
		mpz_init(BSGS_Q[k].x);
		mpz_init(BSGS_Q[k].y);
		mpz_init(BSGS_S[k].x);
		mpz_init(BSGS_S[k].x);
		/*
		mpz_init(BSGS_AMP[k].x);
		mpz_init(BSGS_AMP[k].y);
		*/
	}
	pthread_mutex_lock(&bsgs_thread);
	/* we need to set our base_key to the current BSGS_CURRENT value*/
	mpz_set(base_key,BSGS_CURRENT);
	/*Then add BSGS_N to BSGS_CURRENT*/
	mpz_add(BSGS_CURRENT,BSGS_CURRENT,BSGS_N);
	/*
		We do this in an atomic pthread_mutex operation to not affect others threads
		so BSGS_CURRENT is never the same between threads
	*/
	pthread_mutex_unlock(&bsgs_thread);
	/*
		while base_key is less than n_range_end then:
	*/
	while(mpz_cmp(base_key,n_range_end) < 0)	{
		//gmp_printf("While cycle: base_key : %Zd < n_range_end: %Zd\n",base_key,n_range_end);
		gmp_sprintf(xpoint_str,"%0.64Zx",base_key);

		if(FLAGQUIET == 0) printf("[+] Thread %i: %s\n",thread_number,xpoint_str);
		/*
			Set base_point in to base_key * G
			base_point = base_key * G
		*/
		Scalar_Multiplication(G,&base_point,base_key);	//Scalar_Multiplication(G, &R, K1);
		/*
			We are going to need -( base_point * G)
			point_aux = -( base_point * G)
		*/
		Point_Negation(&base_point,&point_aux);		//Point_Negation(&R,&S);
		/*
			We make a copy of the points OriginalPointsBSGS,
			to work with them in the thread
		*/
		for(k = 0; k < bsgs_point_number; k++)	{
			/*
				We coppy OriginalPointsBSGS[k] into BSGS_Q[k]
				BSGS_Q[k] is our Q point
			*/
			mpz_set(BSGS_Q[k].x,OriginalPointsBSGS[k].x);
			mpz_set(BSGS_Q[k].y,OriginalPointsBSGS[k].y);
			/*
				We need to translate our Actually Q point into our Test Key Space
				Test Key Space : 1 to M
				S = Q - base_key*G
				point_aux is "- base_key*G"
			*/
			Point_Addition(&OriginalPointsBSGS[k],&point_aux,&BSGS_S[k]);
			/*
				We save our BSGS_S again in BSGS_Q
				This BSGS_Q value es now our "Normalize" Q point
				or S in the next formula:  S    = Q - base_key*G
			*/
			mpz_set(BSGS_Q[k].x,BSGS_S[k].x);
			mpz_set(BSGS_Q[k].y,BSGS_S[k].y);
			/*
			mpz_set_ui(BSGS_AMP[k].x,0);
			mpz_set_ui(BSGS_AMP[k].y,0);
			*/
		}
		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
				/*reset main variabler before the do-while cicle*/
				/* Main cycle
					for every a in 0 to bsgs_m
				*/
				salir = 0;
				i = 0;
				do {
					/* We need to test individually every point in BSGS_Q */
					/*Extract BSGS_S.x into xpoint_str*/
					gmp_sprintf(xpoint_str,"%0.64Zx",BSGS_S[k].x);
					/*xpoint_str -> binary*/
					hexs2bin(xpoint_str,(unsigned char*)xpoint_raw);
					//printf("Looking X : %s\n",xpoint_str);
					/* Lookup for the xpoint_raw into the bloom filter*/

					r = bloom_check(&bloom_bPx,xpoint_raw,32);
					if(r) {
						/* Lookup for the xpoint_raw into the full sorted list*/
						tosearch[0] = xpoint_raw[6];
						tosearch[1] = xpoint_raw[7];
						tosearch[2] = xpoint_raw[14];
						tosearch[3] = xpoint_raw[15];
						tosearch[4] = xpoint_raw[22];
						tosearch[5] = xpoint_raw[23];
						tosearch[6] = xpoint_raw[30];
						tosearch[7] = xpoint_raw[31];
						r = bsgs_searchbinary(bPtable,tosearch,bsgs_m,&j);
						if(r)	{
							/* is the xpoint is in the sorted list we HIT one privkey*/
							/* privkey = base_key + aM + b		*/
							/*
							printf("[+] bloom_r = %u\n",bloom_r);
							printf("[+] a = %i, b = %i\n",i,j+1);
							printf("[+] str: %s\n",xpoint_str);
							*/
							mpz_set(keyfound,BSGS_M);
							mpz_mul_ui(keyfound,keyfound,i /* this is a*/);
							mpz_add_ui(keyfound,keyfound,j+1 /* this is b*/);
							mpz_add(keyfound,keyfound,base_key);

							Scalar_Multiplication(G,&point_found,keyfound);
							if(mpz_cmp(point_found.x,OriginalPointsBSGS[k].x) == 0)	{
								gmp_sprintf(xpoint_str,"%0.64Zx",keyfound);
								printf("[+] Thread %i Key found privkey %s\n",thread_number,xpoint_str);

								Scalar_Multiplication(G,&point_aux2,keyfound);
								gmp_sprintf(pubkey,"04%0.64Zx%0.64Zx",point_aux2.x,point_aux2.y);
								printf("[+] Publickey %s\n",pubkey);
								pthread_mutex_lock(&write_keys);
								filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
								if(filekey != NULL)	{
									fprintf(filekey,"Key found privkey %s\nPublickey %s\n",xpoint_str,pubkey);
									fclose(filekey);
								}
								pthread_mutex_unlock(&write_keys);
								bsgs_found[k] = 1;
								salir = 1;
								for(j = 0; j < bsgs_point_number && salir; j++)	{
									salir &= bsgs_found[j];
								}
								if(salir)	{
									printf("All points were found\n");
									exit(0);
								}
							}
							else	{
								/* privkey = base_key + aM - b	*/
								mpz_set(keyfound,BSGS_M);
								mpz_mul_ui(keyfound,keyfound,i /* this is a*/);
								mpz_sub_ui(keyfound,keyfound,j+1 /* this is b*/);
								mpz_add(keyfound,keyfound,base_key);
								Scalar_Multiplication(G,&point_found,keyfound);
								if(mpz_cmp(point_found.x,OriginalPointsBSGS[k].x) == 0)	{
									gmp_sprintf(xpoint_str,"%0.64Zx",keyfound);

									printf("[+] Thread %i Key found privkey %s\n",thread_number,xpoint_str);

									Scalar_Multiplication(G,&point_aux2,keyfound);
									gmp_sprintf(pubkey,"04%0.64Zx%0.64Zx",point_aux2.x,point_aux2.y);
									printf("[+] Publickey %s\n",pubkey);
									pthread_mutex_lock(&write_keys);
									filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
									if(filekey != NULL)	{
										fprintf(filekey,"Key found privkey %s\nPublickey %s\n",xpoint_str,pubkey);
										fclose(filekey);
									}
									pthread_mutex_unlock(&write_keys);
									bsgs_found[k] = 1;
									salir = 1;
									for(j = 0; j < bsgs_point_number && salir; j++)	{
										salir &= bsgs_found[j];
									}
									if(salir)	{
										printf("All points were found\n");
										exit(0);
									}
								}
									/*
								else	{

									printf("[E] Something is wrong!\n");
									gmp_printf("[I] Basekey: 0x%Zx\n",base_key);
									gmp_printf("[I] BSGS_M: 0x%Zx\n",BSGS_M);
									printf("[I] a  = %i , b = %li\n",i,j+1);

								}
									*/
							}
						}
					}
					Point_Addition(&BSGS_Q[k],&BSGS_AMP[i],&BSGS_Q_AMP);
					mpz_set(BSGS_S[k].x,BSGS_Q_AMP.x);
					mpz_set(BSGS_S[k].y,BSGS_Q_AMP.y);
					i++;
				}while( i < bsgs_aux && !bsgs_found[k]);
			} //end if
		}// End for
		steps[thread_number]++;
		pthread_mutex_lock(&bsgs_thread);
		mpz_set(base_key,BSGS_CURRENT);
		mpz_add(BSGS_CURRENT,BSGS_CURRENT,BSGS_N);
		pthread_mutex_unlock(&bsgs_thread);
	}
	for(i = 0; i < bsgs_point_number ; i++)	{
		mpz_clear(BSGS_Q[i].x);
		mpz_clear(BSGS_Q[i].y);
		mpz_clear(BSGS_S[i].x);
		mpz_clear(BSGS_S[i].y);
	}
	free(BSGS_Q);
	free(BSGS_S);
	mpz_clear(base_key);
	mpz_clear(keyfound);
	mpz_clear(base_point.x);
	mpz_clear(base_point.y);
	mpz_clear(point_aux.x);
	mpz_clear(point_aux.y);
	mpz_clear(point_aux2.x);
	mpz_clear(point_aux2.y);
	ends[thread_number] = 1;
}

void *thread_process_bsgs_random(void *vargp)	{
	struct tothread *tt;
	char pubkey[131],xpoint_str[65],xpoint_raw[32],tosearch[BSGS_XVALUE_RAM];
	char *aux_c;
	mpz_t base_key,keyfound;
	FILE *filekey;
	struct Point base_point,point_aux,point_aux2,point_found;
	struct Point *BSGS_Q, *BSGS_S,BSGS_Q_AMP /* ,*BSGS_AMP*/;
	mpz_t n_range_random;
	int64_t j;
	uint32_t i,k,r,salir,thread_number;
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	mpz_init(n_range_random);
	mpz_init(base_key);
	mpz_init(keyfound);
	mpz_init(base_point.x);
	mpz_init(base_point.y);
	mpz_init(point_aux.x);
	mpz_init(point_aux.y);
	mpz_init(point_aux2.x);
	mpz_init(point_aux2.y);

	mpz_init(point_found.x);
	mpz_init(point_found.y);


	mpz_init(BSGS_Q_AMP.x);
	mpz_init(BSGS_Q_AMP.y);

	BSGS_S = malloc(bsgs_point_number*sizeof(struct Point));
	BSGS_Q = malloc(bsgs_point_number*sizeof(struct Point));
	/*
	BSGS_S_1 = malloc(bsgs_point_number*sizeof(struct Point));
	BSGS_Q_2 = malloc(bsgs_point_number*sizeof(struct Point));
	*/
	//BSGS_AMP = malloc(bsgs_point_number*sizeof(struct Point));
	if(BSGS_Q == NULL || BSGS_S == NULL /*|| BSGS_AMP == NULL*/)	{
		fprintf(stderr,"[E] error malloc(): thread_process_bsgs\n");
		exit(0);
	}
	/* We initializing all BSGS_Q values this is GMP related stuff*/
	for(k = 0; k < bsgs_point_number; k++)	{
		mpz_init(BSGS_Q[k].x);
		mpz_init(BSGS_Q[k].y);
		mpz_init(BSGS_S[k].x);
		mpz_init(BSGS_S[k].x);
		/*
		mpz_init(BSGS_AMP[k].x);
		mpz_init(BSGS_AMP[k].y);
		*/
	}
	pthread_mutex_lock(&bsgs_thread);
	/*      | Start Range   | End Range    |
		None  | 1					  	|	EC.N			   |
-b  bit		| Min bit value |Max bit value |
-r  A:B   | A             | B 					 |
	*/
	// set n_range_random = random(end_range - start range)
	mpz_urandomm (n_range_random,state,n_range_diff);

	// base key =  start + random value
	mpz_add(base_key,n_range_start,n_range_random);
	pthread_mutex_unlock(&bsgs_thread);
	/*
		while base_key is less than n_range_end then:
	*/
	while(mpz_cmp(base_key,n_range_end) < 0)	{
		//gmp_printf("While cycle: base_key : %Zd < n_range_end: %Zd\n",base_key,n_range_end);
		gmp_sprintf(xpoint_str,"%0.64Zx",base_key);
		if(FLAGQUIET == 0) printf("[+] Thread %i: %s\n",thread_number,xpoint_str);
		/*
			Set base_point in to base_key * G
			base_point = base_key * G
		*/
		Scalar_Multiplication(G,&base_point,base_key);	//Scalar_Multiplication(G, &R, K1);
		/*
			We are going to need -( base_point * G)
			point_aux = -( base_point * G)
		*/
		Point_Negation(&base_point,&point_aux);		//Point_Negation(&R,&S);
		/*
			We make a copy of the points OriginalPointsBSGS,
			to work with them in the thread
		*/
		for(k = 0; k < bsgs_point_number; k++)	{
			/*
				We coppy OriginalPointsBSGS[k] into BSGS_Q[k]
				BSGS_Q[k] is our Q point
			*/
			mpz_set(BSGS_Q[k].x,OriginalPointsBSGS[k].x);
			mpz_set(BSGS_Q[k].y,OriginalPointsBSGS[k].y);
			/*
				We need to translate our Actually Q point into our Test Key Space
				Test Key Space : 1 to M
				S = Q - base_key*G
				point_aux is "- base_key*G"
			*/
			Point_Addition(&OriginalPointsBSGS[k],&point_aux,&BSGS_S[k]);
			/*
				We save our BSGS_S again in BSGS_Q
				This BSGS_Q value es now our "Normalize" Q point
				or S in the next formula:  S    = Q - base_key*G
			*/
			mpz_set(BSGS_Q[k].x,BSGS_S[k].x);
			mpz_set(BSGS_Q[k].y,BSGS_S[k].y);
			/*
			mpz_set_ui(BSGS_AMP[k].x,0);
			mpz_set_ui(BSGS_AMP[k].y,0);
			*/
		}
		/* We need to test individually every point in BSGS_Q */
		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
			/*reset main variabler before the do-while cicle*/
			salir = 0;
			i = 0;
			/* Main cycle
				for every a in 0 to bsgs_aux
			*/
			do {
					gmp_sprintf(xpoint_str,"%0.64Zx",BSGS_S[k].x);
					hexs2bin(xpoint_str,(unsigned char*)xpoint_raw);


					r = bloom_check(&bloom_bPx,xpoint_raw,32);
					if(r) {

						/* Lookup for the xpoint_raw into the full sorted list*/
						tosearch[0] = xpoint_raw[6];
						tosearch[1] = xpoint_raw[7];
						tosearch[2] = xpoint_raw[14];
						tosearch[3] = xpoint_raw[15];
						tosearch[4] = xpoint_raw[22];
						tosearch[5] = xpoint_raw[23];
						tosearch[6] = xpoint_raw[30];
						tosearch[7] = xpoint_raw[31];
						r = bsgs_searchbinary(bPtable,tosearch,bsgs_m,&j);
						if(r)	{
							/* is the xpoint is in the sorted list we HIT one privkey*/
							/* privkey = base_key + aM + b		*/
							//printf("[+] a = %i, b = %i\n",i,j+1);
							mpz_set(keyfound,BSGS_M);
							mpz_mul_ui(keyfound,keyfound,i /* this is a*/);
							mpz_add_ui(keyfound,keyfound,j+1 /* this is b*/);
							mpz_add(keyfound,keyfound,base_key);

							Scalar_Multiplication(G,&point_found,keyfound);
							if(mpz_cmp(point_found.x,OriginalPointsBSGS[k].x) == 0)	{
								gmp_sprintf(xpoint_str,"%0.64Zx",keyfound);
								printf("[+] Thread %i Key found privkey %s\n",thread_number,xpoint_str);

								Scalar_Multiplication(G,&point_aux2,keyfound);
								gmp_sprintf(pubkey,"04%0.64Zx%0.64Zx",point_aux2.x,point_aux2.y);
								printf("[+] Publickey %s\n",pubkey);
								pthread_mutex_lock(&write_keys);
								filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
								if(filekey != NULL)	{
									fprintf(filekey,"Key found privkey %s\nPublickey %s\n",xpoint_str,pubkey);
									fclose(filekey);
								}
								pthread_mutex_unlock(&write_keys);
								bsgs_found[k] = 1;
								salir = 1;
								for(j = 0; j < bsgs_point_number && salir; j++)	{
									salir &= bsgs_found[j];
								}
								if(salir)	{
									printf("All points were found\n");
									exit(0);
								}
							}
							else	{
								/* then the key mus be */
								/* privkey = base_key + aM - b		*/
								mpz_set(keyfound,BSGS_M);
								mpz_mul_ui(keyfound,keyfound,i /* this is a*/);
								mpz_sub_ui(keyfound,keyfound,j+1 /* this is b*/);
								mpz_add(keyfound,keyfound,base_key);
								Scalar_Multiplication(G,&point_found,keyfound);
								if(mpz_cmp(point_found.x,OriginalPointsBSGS[k].x) == 0)	{
									gmp_sprintf(xpoint_str,"%0.64Zx",keyfound);

									printf("[+] Thread %i Key found privkey %s\n",thread_number,xpoint_str);

									Scalar_Multiplication(G,&point_aux2,keyfound);
									gmp_sprintf(pubkey,"04%0.64Zx%0.64Zx",point_aux2.x,point_aux2.y);
									printf("[+] Publickey %s\n",pubkey);
									pthread_mutex_lock(&write_keys);
									filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
									if(filekey != NULL)	{
										fprintf(filekey,"Key found privkey %s\nPublickey %s\n",xpoint_str,pubkey);
										fclose(filekey);
									}
									pthread_mutex_unlock(&write_keys);
									bsgs_found[k] = 1;
									salir = 1;
									for(j = 0; j < bsgs_point_number && salir; j++)	{
										salir &= bsgs_found[j];
									}
									if(salir)	{
										printf("All points were found\n");
										exit(0);
									}
								}
								/*
								else	{
									printf("[E] Something is wrong!\n");
									gmp_printf("[I] Basekey: 0x%Zx\n",base_key);
									gmp_printf("[I] BSGS_M: 0x%Zx\n",BSGS_M);
									printf("[I] a  = %i , b = %li\n",i,j+1);
								}
								*/
							}
						}

					}
					Point_Addition(&BSGS_Q[k],&BSGS_AMP[i],&BSGS_Q_AMP);
					mpz_set(BSGS_S[k].x,BSGS_Q_AMP.x);
					mpz_set(BSGS_S[k].y,BSGS_Q_AMP.y);
					i++;
				} while( i < bsgs_aux && !bsgs_found[k]);
			}	//End if
		} // End for with k bsgs_point_number
		steps[thread_number]++;
		pthread_mutex_lock(&bsgs_thread);
		mpz_urandomm (n_range_random,state,n_range_diff);
		mpz_add(base_key,n_range_start,n_range_random);
		pthread_mutex_unlock(&bsgs_thread);
	}
	for(i = 0; i < bsgs_point_number ; i++)	{
		mpz_clear(BSGS_Q[i].x);
		mpz_clear(BSGS_Q[i].y);
		mpz_clear(BSGS_S[i].x);
		mpz_clear(BSGS_S[i].y);
	}
	free(BSGS_Q);
	free(BSGS_S);
	mpz_clear(base_key);
	mpz_clear(keyfound);
	mpz_clear(base_point.x);
	mpz_clear(base_point.y);
	mpz_clear(point_aux.x);
	mpz_clear(point_aux.y);
	mpz_clear(point_aux2.x);
	mpz_clear(point_aux2.y);
	ends[thread_number] = 1;
}
