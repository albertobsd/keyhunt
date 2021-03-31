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
#include <inttypes.h>
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"
#include "bloom/bloom.h"
#include "custombloom/bloom.h"
#include "sha3/sha3.h"
#include "util.h"
#ifdef WIN32
	#include <windows.h>
#endif

#define CRYPTO_NONE 0
#define CRYPTO_BTC 1
#define CRYPTO_ETH 2
#define CRYPTO_ALL 3

#define MODE_XPOINT 0
#define MODE_ADDRESS 1
#define MODE_BSGS 2
#define MODE_RMD160 3

#define SEARCH_UNCOMPRESS 0
#define SEARCH_COMPRESS 1
#define SEARCH_BOTH 2


struct Point {
	mpz_t x;
	mpz_t y;
};

struct Elliptic_Curve {
	mpz_t p;
	mpz_t n;
};

struct bsgs_xvalue	{
	uint8_t value[6];
	uint64_t index;
};

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt; 		//Number thread
	char *rs; 	//range start
	char *rpt;	//rng per thread
};

struct bPload	{
	uint64_t from;
	uint64_t to;
	uint64_t counter;
};


const char *version = "0.1.20210331";
const char *EC_constant_N = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
const char *EC_constant_P = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
const char *EC_constant_Gx = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const char *EC_constant_Gy = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
struct Point DoublingG[256];

void Point_Doubling(struct Point *P, struct Point *R);
void Point_Addition(struct Point *P, struct Point *Q, struct Point *R);
void Scalar_Multiplication(struct Point P, struct Point *R, mpz_t m);
void Point_Negation(struct Point *A, struct Point *S);
int searchbinary(struct address_value *buffer,char *data,int64_t _N);
void sleep_ms(int milliseconds);

void _sort(struct address_value *arr,int64_t N);
void _insertionsort(struct address_value *arr, int64_t n);
void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n);
void _swap(struct address_value *a,struct address_value *b);
int64_t _partition(struct address_value *arr, int64_t n);
void _myheapsort(struct address_value	*arr, int64_t n);
void _heapify(struct address_value *arr, int64_t n, int64_t i);

void bsgs_sort(struct bsgs_xvalue *arr,int64_t n);
void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_introsort(struct bsgs_xvalue *arr,uint32_t depthLimit, int64_t n);
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b);
void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i);
int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n);


int bsgs_searchbinary(struct bsgs_xvalue *arr,char *data,int64_t _N,uint64_t *r_value);
int bsgs_secondcheck(mpz_t start_range,uint32_t a,struct Point *target,mpz_t *private);

void *thread_process(void *vargp);
void *thread_process_bsgs(void *vargp);
void *thread_process_bsgs_random(void *vargp);
void *thread_bPload(void *vargp);
void *thread_bPloadFile(void *vargp);

void init_doublingG(struct Point *P);
char *publickeytohashrmd160(char *pkey,int length);
char *pubkeytopubaddress(char *pkey,int length);
//char *pubkeytopubaddress_eth(char *pkey,int length);

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *modes[4] = {"xpoint","address","bsgs","rmd160"};
const char *cryptos[3] = {"btc","eth","all"};
const char *publicsearch[3] = {"uncompress","compress","both"};
const char *default_filename = "addresses.txt";

pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t threads_end;
pthread_mutex_t bsgs_thread;

struct Elliptic_Curve EC;
struct bloom bloom;
struct Point G;

unsigned int *steps = NULL;
unsigned int *ends = NULL;
uint32_t N = 0;
gmp_randstate_t state;

uint64_t N_SECUENTIAL_MAX = 0xffffffff;
uint64_t DEBUGCOUNT = 0x100000;

int FLAGDEBUG = 0;
int FLAGQUIET = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;
int OUTPUTSECONDS = 30;
int FLAGSEARCH = 2;
int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGFILE = 0;
int FLAGVANITY = 0;
int FLAGMODE = MODE_ADDRESS;
int FLAGCRYPTO = 0;
int FLAGALREADYSORTED = 0;
int FLAGRAWDATA	= 0;
int FLAGRANDOM = 0;
int FLAG_N = 0;
int FLAGPRECALCUTED_P_FILE = 0;
int FLAGPRECALCUTED_MP_FILE = 0;

int len_vanity;
int bitrange;
char *vanity;
char *range_start;
char *range_end;

uint64_t BSGS_XVALUE_RAM = 6;
uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;

/*
BSGS Variables
*/
int *bsgs_found;
struct Point *OriginalPointsBSGS;
struct bsgs_xvalue *bPtable;
struct address_value *addressTable;
struct custombloom bloom_bP[256];
struct custombloom bloom_bPx2nd; //Second Bloom filter check
uint64_t bloom_bP_totalbytes = 0;
char *precalculated_p_filename;
uint64_t bsgs_m;
uint64_t bsgs_m2;

unsigned long int bsgs_aux;
uint32_t bsgs_point_number;
mpz_t BSGS_CURRENT;
mpz_t BSGS_R;
mpz_t BSGS_AUX;
mpz_t BSGS_N;
mpz_t BSGS_M;					//M is squareroot(N)
mpz_t BSGS_M2;
mpz_t TWO;
mpz_t MPZAUX;
struct Point BSGS_P;			//Original P is actually G, but this P value change over time for calculations
struct Point BSGS_MP;			//MP values this is m * P
struct Point BSGS_MP2;			//MP values this is m2 * P
struct Point *BSGS_AMP;
struct Point *BSGS_AMP2;

struct Point point_temp,point_temp2;	//Temp value for some process

mpz_t n_range_start;
mpz_t n_range_end;
mpz_t n_range_diff;
mpz_t n_range_aux;

int main(int argc, char **argv)	{
	char buffer[1024];
	char temporal[65];
	char rawvalue[32];
	struct tothread *tt;	//tothread
	Tokenizer t,tokenizerbsgs,tokenizer_xpoint;	//tokenizer
	char *filename,*precalculated_mp_filename;
	FILE *fd;
	char *hextemp,*aux,*aux2,*pointx_str,*pointy_str;
	uint64_t i,seconds;
	uint64_t j,total_precalculated,PERTHREAD,BASE,PERTHREAD_R;
	int readed,s,continue_flag,check_flag,r,lenaux,lendiff;
	mpz_t total,pretotal,debugcount_mpz,Ysquared,mpz_aux,mpz_aux2;
	clock_t c_beging,c_ending, time_spent;
	struct bPload *temp;

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


	while ((c = getopt(argc, argv, "dehqRwb:c:f:g:k:l:m:n:p:r:s:t:v:-:")) != -1) {
		switch(c) {
			case 'h':
				printf("\nUsage:\n-h\t\tshow this help\n");
				printf("-a file\t\tfile is a binary raw file with the aMP points precalculated. Just work with -m bsgs\n");
				printf("-b bits\t\tFor some puzzles you only need some numbers of bits in the test keys.\n");
				printf("\t\tThis option only is valid with the Random option -R\n");
				printf("-c crypto\tSearch for specific crypo. < btc, eth, all > valid only w/ -m address \n");
				printf("-e\t\tThe file is already Sorted descendent. This skip the sorting process.\n");
				printf("\t\tYour file MUST be sordted if no you are going to lose collisions\n");
				printf("-f file\t\tSpecify filename with addresses or xpoints or uncompressed public keys\n");
				printf("-g count\tJust for the stats, mark as counted every debugcount keys	\n");
				printf("-k value\tUse this with bsgs mode, k value is factor for M, more speed but more RAM use wisely\n");
				printf("-l look\tWhat type of address/hash160 are you looking for < compress , uncompress , both>\n");
				printf("-m mode\t\tmode of search for cryptos. ( bsgs , xpoint , rmd160 , address ) default: address (more slow)\n");
				printf("-n uptoN\tCheck for N secuential numbers before the random chossen this only work with -R option\n");
				printf("\t\tUse -n to set the N for the BSGS process. Bigger N more RAM needed\n");
				printf("-p file\t\tfile is a binary raw file with the bP points precalculated. Just work with -m bsgs\n");
				printf("-q\t\tset quiet the thread output\n");
				printf("-r SR:EN\tStarRange:EndRange, the end range can be omited for search from start range to N-1 ECC value\n");
				printf("-R\t\tRandom this is the default behaivor\n");
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
					mpz_init(MPZAUX);
					mpz_pow_ui(MPZAUX,TWO,bitrange-1);
					bit_range_str_min = mpz_get_str(NULL,16,MPZAUX);
					mpz_pow_ui(MPZAUX,TWO,bitrange);
					mpz_sub_ui(MPZAUX,MPZAUX,1);
					bit_range_str_max = mpz_get_str(NULL,16,MPZAUX);
					if(bit_range_str_min == NULL||bit_range_str_max == NULL)	{
						fprintf(stderr,"[E] error malloc()\n");
						exit(0);
					}
					printf("[+] Min range: %s\n",bit_range_str_min);
					printf("[+] Max range: %s\n",bit_range_str_max);
					FLAGBITRANGE = 1;
					mpz_clear(MPZAUX);
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
			case 'd':
				FLAGDEBUG = 1;
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

			case 'l':
				switch(indexOf(optarg,publicsearch,3)) {
					case SEARCH_UNCOMPRESS:
						FLAGSEARCH = SEARCH_UNCOMPRESS;
						printf("[+] Search uncompress only\n");
					break;
					case SEARCH_COMPRESS:
						FLAGSEARCH = SEARCH_COMPRESS;
						printf("[+] Search compress only\n");
					break;
					case SEARCH_BOTH:
						FLAGSEARCH = SEARCH_BOTH;
						printf("[+] Search both compress and uncompress\n");
					break;
				}
			break;
			case 'm':
				switch(indexOf(optarg,modes,4)) {
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
					case MODE_RMD160:
						FLAGMODE = MODE_RMD160;
						printf("[+] Setting mode rmd160\n");
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
				FLAGQUIET	= 1;
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
				if(optarg != NULL)	{
					stringtokenizer(optarg,&t);
					switch(t.n)	{
						case 1:
							range_start = nextToken(&t);
							if(isValidHex(range_start)) {
									FLAGRANGE = 1;
									range_end = (char*) EC_constant_N;
							}
							else	{
								fprintf(stderr,"[E] Invalid hexstring : %s.\n",range_start);
							}
						break;
						case 2:
							range_start = nextToken(&t);
							range_end	 = nextToken(&t);
							if(isValidHex(range_start) && isValidHex(range_end)) {
									FLAGRANGE = 1;
							}
							else	{
								if(isValidHex(range_start)) {
									printf("[E] Invalid hexstring : %s\n",range_start);
								}
								else	{
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
				if(OUTPUTSECONDS < 0)	{
					OUTPUTSECONDS = 30;
				}
				if(OUTPUTSECONDS == 0)	{
					printf("[+] Turn off stats output\n");
				}
				else	{
					printf("[+] Stats output every %u seconds\n",OUTPUTSECONDS);
				}
			break;
			case 't':
				NTHREADS = strtol(optarg,NULL,10);
				if(NTHREADS <= 0)	{
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
			default:
				printf("[E] Unknow opcion %c\n",c);
			break;
		}
	}


	if(DEBUGCOUNT	> N_SECUENTIAL_MAX)	{
		DEBUGCOUNT = N_SECUENTIAL_MAX - 1;

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
	if(FLAGMODE == MODE_ADDRESS && FLAGCRYPTO == CRYPTO_NONE) {	//When none crypto is defined the default search is for Bitcoin
		FLAGCRYPTO = CRYPTO_BTC;
		printf("[+] Setting search for btc adddress\n");
	}
	mpz_init(n_range_start);
	mpz_init(n_range_end);
	mpz_init(n_range_diff);

	if(FLAGRANGE) {
		mpz_set_str(n_range_start,range_start,16);
		mpz_set_str(n_range_end,range_end,16);
		if(mpz_cmp(n_range_start,n_range_end) != 0 ) {
			if(mpz_cmp(n_range_start,EC.n) < 0 && mpz_cmp(n_range_end,EC.n) <= 0)	{
				if(mpz_cmp(n_range_start,n_range_end) > 0) {
					fprintf(stderr,"[W] Opps, start range can't be great than end range. Swapping them\n");
					mpz_init(n_range_aux);
					mpz_set(n_range_aux,n_range_start);
					mpz_set(n_range_start,n_range_end);
					mpz_set(n_range_end,n_range_aux);
					mpz_clear(n_range_aux);
				}
				mpz_sub(n_range_diff,n_range_end,n_range_start);
			}
			else	{
				fprintf(stderr,"[E] Start and End range can't be great than N\nFallback to random mode!\n");
				FLAGRANGE = 0;
			}
		}
		else	{
			fprintf(stderr,"[E] Start and End range can't be the same\nFallback to random mode!\n");
			FLAGRANGE = 0;
		}
	}
	if(FLAGMODE != MODE_BSGS)	{
		if(FLAGRANGE == 0 && FLAGBITRANGE == 0)	{
			mpz_set_str(n_range_start,"1",10);
			mpz_set(n_range_end,EC.n);
			mpz_sub(n_range_diff,n_range_end,n_range_start);
		}
		else	{
			if(FLAGBITRANGE)	{
				mpz_set_str(n_range_start,bit_range_str_min,16);
				mpz_set_str(n_range_end,bit_range_str_max,16);
				mpz_sub(n_range_diff,n_range_end,n_range_start);
			}
			else	{
				if(FLAGRANGE == 0)	{
					fprintf(stderr,"[W] WTF!\n");
				}
			}
		}
	}

	N =0;
	if(FLAGMODE != MODE_BSGS)	{
		aux = malloc(1000);
		if(aux == NULL)	{
			fprintf(stderr,"[E] error malloc()\n");
		}
		switch(FLAGMODE)	{
			case MODE_ADDRESS:
				while(!feof(fd))	{
					hextemp = fgets(aux,998,fd);
					if(hextemp == aux)	{
						trim(aux," \t\n\r");
						r = strlen(aux);
						if(r > 10)	{ //Any length for invalid Address?
							if(r > MAXLENGTHADDRESS)	{
								MAXLENGTHADDRESS = r;
							}
							N++;
						}
					}
				}
				MAXLENGTHADDRESS = 32;
			break;
			case MODE_RMD160:
				if(FLAGRAWDATA) {
					while(!feof(fd))	{
						if(fread(aux,1,20,fd) == 20)	{
							N++;
						}
					}
				}
				else	{
					while(!feof(fd))	{
						hextemp = fgets(aux,998,fd);
						if(hextemp == aux)	{
							trim(aux," \t\n\r");
							r = strlen(aux);
							if(r == 40)	{ //Any length for invalid Address?
								N++;
							}
						}
					}
				}
				MAXLENGTHADDRESS = 20;
			break;
			case MODE_XPOINT:
				if(FLAGRAWDATA) {
					while(!feof(fd))	{
						if(fread(aux,1,32,fd) == 32)	{
							N++;
						}
					}
				}
				else	{
					while(!feof(fd))	{
						hextemp = fgets(aux,998,fd);
						if(hextemp == aux)	{
							trim(aux," \t\n\r");
							r = strlen(aux);
							if(r >= 32)	{ //Any length for invalid Address?
								N++;
							}
						}
					}
				}
				MAXLENGTHADDRESS = 32;
			break;
		}
		free(aux);
		if(N == 0)	{
			fprintf(stderr,"[E] There is no valid data in the file\n");
			exit(0);
		}
		fseek(fd,0,SEEK_SET);

		printf("[+] Allocating memory for %u elements: %.2f MB\n",N,(double)(sizeof(struct address_value)*N)/1048576);
		i = 0;

		do {
			addressTable = malloc(sizeof(struct address_value)*N);
			i++;
		} while(addressTable == NULL && i < 10);
		if(addressTable == NULL)	{
			fprintf(stderr,"[E] Can't alloc memory for %u elements\n",N);
			exit(0);
		}
		printf("[+] Initializing bloom filter for %u elements.\n",N);
		if(N <= 1000)	{
			if(bloom_init2(&bloom,1000,0.00001)	== 1){
				fprintf(stderr,"[E] error bloom_init for 10000 elements.\n");
				exit(0);
			}
		}
		else	{
			if(bloom_init2(&bloom,N,0.00001)	== 1){
				fprintf(stderr,"[E] error bloom_init for %u elements.\n",N);
				fprintf(stderr,"[+] man enough is enough stop it\n");
				exit(0);
			}
		}
		printf("[+] Loading data to the bloomfilter\n");
		i = 0;
		switch (FLAGMODE) {
			case MODE_ADDRESS:
				aux = malloc(2*MAXLENGTHADDRESS);
				if(aux == NULL)	{
					fprintf(stderr,"[E] error malloc()\n");
					exit(0);
				}
				while(i < N)	{
					memset(aux,0,2*MAXLENGTHADDRESS);
					memset((void *)&addressTable[i],0,sizeof(struct address_value));
					hextemp = fgets(aux,2*MAXLENGTHADDRESS,fd);
					if(hextemp == aux)	{
						trim(aux," \t\n\r");
						bloom_add(&bloom, aux,MAXLENGTHADDRESS);
						memcpy(addressTable[i].value,aux,20);
						i++;
					}
					else	{
						trim(aux," \t\n\r");
						fprintf(stderr,"[E] Omiting line : %s\n",aux);
					}
				}
			break;
			case MODE_XPOINT:
				if(FLAGRAWDATA)	{
					aux = malloc(MAXLENGTHADDRESS);
					if(aux == NULL)	{
						fprintf(stderr,"[E] error malloc()\n");
						exit(0);
					}
					while(i < N)	{
						if(fread(aux,1,MAXLENGTHADDRESS,fd) == 32)	{
							memcpy(addressTable[i].value,aux,20);
							bloom_add(&bloom, aux,MAXLENGTHADDRESS);
						}
						i++;
					}
				}
				else	{
					aux = malloc(5*MAXLENGTHADDRESS);
					if(aux == NULL)	{
						fprintf(stderr,"[E] error malloc()\n");
						exit(0);
					}
					while(i < N)	{
						memset(aux,0,5*MAXLENGTHADDRESS);
						hextemp = fgets(aux,(5*MAXLENGTHADDRESS) -2,fd);
						memset((void *)&addressTable[i],0,sizeof(struct address_value));

						if(hextemp == aux)	{
							trim(aux," \t\n\r");
							stringtokenizer(aux,&tokenizer_xpoint);
							hextemp = nextToken(&tokenizer_xpoint);
							lenaux = strlen(hextemp);
							if(isValidHex(hextemp)) {
								switch(lenaux)	{
									case 64:	/*X value*/
										r = hexs2bin(aux,rawvalue);
										if(r)	{
											memcpy(addressTable[i].value,rawvalue,20);
											bloom_add(&bloom,rawvalue,MAXLENGTHADDRESS);
										}
										else	{
											fprintf(stderr,"[E] error hexs2bin\n");
										}
									break;
									case 66:	/*Compress publickey*/
									r = hexs2bin(aux+2,rawvalue);
										if(r)	{
											memcpy(addressTable[i].value,rawvalue,20);
											bloom_add(&bloom,rawvalue,MAXLENGTHADDRESS);
										}
										else	{
											fprintf(stderr,"[E] error hexs2bin\n");
										}
									break;
									case 130:	/* Uncompress publickey length*/
										memset(temporal,0,65);
										memcpy(temporal,aux+2,64);
										r = hexs2bin(temporal,rawvalue);
										if(r)	{
												memcpy(addressTable[i].value,rawvalue,20);
												bloom_add(&bloom,rawvalue,MAXLENGTHADDRESS);
										}
										else	{
											fprintf(stderr,"[E] error hexs2bin\n");
										}
									break;
									default:
										fprintf(stderr,"[E] Omiting line unknow length size %i: %s\n",lenaux,aux);
									break;
								}
							}
							else	{
								fprintf(stderr,"[E] Ignoring invalid hexvalue %s\n",aux);
							}
							freetokenizer(&tokenizer_xpoint);
						}
						else	{
							fprintf(stderr,"[E] Omiting line : %s\n",aux);
							N--;
						}

						i++;
					}
				}
			break;
			case MODE_RMD160:
				if(FLAGRAWDATA)	{
					aux = malloc(MAXLENGTHADDRESS);
					if(aux == NULL)	{
						fprintf(stderr,"[E] error malloc()\n");
						exit(0);
					}
					while(i < N)	{
						if(fread(aux,1,MAXLENGTHADDRESS,fd) == 20)	{
							memcpy(addressTable[i].value,aux,20);
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
					while(i < N)	{
						memset(aux,0,3*MAXLENGTHADDRESS);
						hextemp = fgets(aux,3*MAXLENGTHADDRESS,fd);
						memset(addressTable[i].value,0,20);
						if(hextemp == aux)	{
							trim(aux," \t\n\r");
							lenaux = strlen(aux);
							if(isValidHex(aux)) {
								if(lenaux == 40)	{
									if(hexs2bin(aux,addressTable[i].value))	{
											bloom_add(&bloom,addressTable[i].value,MAXLENGTHADDRESS);
									}
									else	{
										fprintf(stderr,"[E] error hexs2bin\n");
									}
								}
								else	{
									fprintf(stderr,"[E] Ignoring invalid length line %s\n",aux);
								}
							}
							else	{
								fprintf(stderr,"[E] Ignoring invalid hexvalue %s\n",aux);
							}
						}
						else	{
							fprintf(stderr,"[E] Omiting line : %s\n",aux);
						}
						i++;
					}
				}
			break;
		}
		free(aux);
		fclose(fd);
		printf("[+] Bloomfilter completed\n");
		if(FLAGALREADYSORTED)	{
			printf("[+] File mark already sorted, skipping sort proccess\n");
			printf("[+] %i values were loaded\n",N);
			_sort(addressTable,N);
		}
		else	{
			printf("[+] Sorting data\n");
			_sort(addressTable,N);
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
		while(!feof(fd))	{
			if(fgets(aux,1022,fd) == aux)	{
				trim(aux," \t\n\r");
				if(strlen(aux) >= 128)	{	//Length of a full address in hexadecimal without 04
						N++;
				}else	{
					if(strlen(aux) >= 66)	{
						N++;
					}
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
		mpz_init(Ysquared);
		mpz_init(mpz_aux);
		mpz_init(mpz_aux2);
		i = 0;
		while(!feof(fd))	{
			if(fgets(aux,1022,fd) == aux)	{
				trim(aux," \t\n\r");
				if(strlen(aux) >= 66)	{
					stringtokenizer(aux,&tokenizerbsgs);
					aux2 = nextToken(&tokenizerbsgs);
					memset(pointx_str,0,65);
					memset(pointy_str,0,65);
					switch(strlen(aux2))	{
						case 66:	//Compress
							memcpy(pointx_str,aux2+2,64);
							if(isValidHex(pointx_str))	{
								mpz_init_set_str(OriginalPointsBSGS[i].x,pointx_str,16);
								mpz_init(OriginalPointsBSGS[i].y);
								mpz_pow_ui(mpz_aux,OriginalPointsBSGS[i].x,3);
								mpz_add_ui(mpz_aux2,mpz_aux,7);
								mpz_mod(Ysquared,mpz_aux2,EC.p);
								mpz_add_ui(mpz_aux,EC.p,1);
								mpz_fdiv_q_ui(mpz_aux2,mpz_aux,4);
								mpz_powm(OriginalPointsBSGS[i].y,Ysquared,mpz_aux2,EC.p);
								mpz_sub(mpz_aux, EC.p,OriginalPointsBSGS[i].y);
								switch(aux2[1])	{
									case '2':
										if(mpz_tstbit(OriginalPointsBSGS[i].y, 0) == 1)	{
											mpz_set(OriginalPointsBSGS[i].y,mpz_aux);
										}
										i++;
									break;
									case '3':
										if(mpz_tstbit(OriginalPointsBSGS[i].y, 0) == 0)	{
											mpz_set(OriginalPointsBSGS[i].y,mpz_aux);
										}
										i++;
									break;
									default:
										fprintf(stderr,"[E] Some invalid bit in the line: %c\n",aux2[1]);
										N--;
									break;
								}
							}
							else	{
								fprintf(stderr,"[E] Some invalid hexdata in the file: %s\n",aux2);
								N--;
							}
						break;
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
		if(N > 0)	{
			printf("[+] Added %u points from file\n",bsgs_point_number);
		}
		else	{
			printf("[E] The file don't have any valid publickeys\n");
			exit(0);
		}
		mpz_init(BSGS_N);
		mpz_init(BSGS_M);
		mpz_init(point_temp.x);
		mpz_init(point_temp.y);
		mpz_init(point_temp2.x);
		mpz_init(point_temp2.y);
		mpz_init_set_ui(BSGS_MP.x,0);
		mpz_init_set_ui(BSGS_MP.y,0);
		mpz_init_set_ui(BSGS_MP2.x,0);
		mpz_init_set_ui(BSGS_MP2.y,0);

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
		mpz_init(BSGS_M2);

		mpz_mul_ui(BSGS_M,BSGS_M,KFACTOR);


		mpz_cdiv_q_ui(BSGS_M2,BSGS_M,20);
		bsgs_m2 =  mpz_get_ui(BSGS_M2);


		mpz_cdiv_q(BSGS_AUX,BSGS_N,BSGS_M);
		mpz_cdiv_r(BSGS_R,BSGS_N,BSGS_M);
		if(mpz_cmp_ui(BSGS_R,0) != 0 ) {
			mpz_mul(BSGS_N,BSGS_M,BSGS_AUX);
		}
		bsgs_m = (uint64_t)((uint64_t) bsgs_m * (uint64_t)KFACTOR);
		bsgs_aux = mpz_get_ui(BSGS_AUX);
		DEBUGCOUNT = (uint64_t)((uint64_t)bsgs_m * (uint64_t)bsgs_aux);

		printf("[+] Setting N up to %llu.\n",(long long unsigned int)DEBUGCOUNT);

		for(i=0; i< 256; i++)	{
			if(((int)(bsgs_m/256)) > 1000)	{
				if(custombloom_init2(&bloom_bP[i],(int)(bsgs_m/256),0.000001)	== 1){
					fprintf(stderr,"[E] error bloom_init [%"PRIu64"]\n",i);
					exit(0);
				}
			}
			else	{
				if(custombloom_init2(&bloom_bP[i],1000,0.000001)	== 1){
					fprintf(stderr,"[E] error bloom_init for 1000 elements [%"PRIu64"]\n",i);
					exit(0);
				}
			}
			bloom_bP_totalbytes += bloom_bP[i].bytes;
			if(FLAGDEBUG) custombloom_print(&bloom_bP[i]);
		}
		printf("[+] Init 1st bloom filter for %lu elements : %.2f MB\n",bsgs_m,(float)((uint64_t)bloom_bP_totalbytes/(uint64_t)1048576));

		if(bsgs_m2 > 1000)	{
			if(custombloom_init2(&bloom_bPx2nd,bsgs_m2,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init for %lu elements\n",bsgs_m2);
				exit(0);
			}
		}
		else	{
			if(custombloom_init2(&bloom_bPx2nd,1000,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init for 1000 elements\n");
				exit(0);
			}
		}
		if(FLAGDEBUG) custombloom_print(&bloom_bPx2nd);
		printf("[+] Init 2nd bloom filter for %lu elements : %.2f MB\n",bsgs_m2,(double)((double)bloom_bPx2nd.bytes/(double)1048576));
		//bloom_print(&bloom_bPx2nd);

		Scalar_Multiplication(G,&BSGS_MP,BSGS_M);
		Scalar_Multiplication(G,&BSGS_MP2,BSGS_M2);

		printf("[+] Allocating %.1f MB for %"PRIu64" aMP Points\n",(double)(((double)(bsgs_aux*sizeof(struct Point)))/(double)1048576),bsgs_aux);
		i = 0;
		BSGS_AMP = malloc((uint64_t)((uint64_t)bsgs_aux*(uint64_t)sizeof(struct Point)));
		if(BSGS_AMP == NULL)	{
			printf("[E] error malloc()\n");
			exit(0);
		}

		//printf("[+] Allocating %.1f MB for aMP Points (2nd)\n",(float)(((uint64_t)(bsgs_m2*sizeof(struct Point)))/(uint64_t)1048576));
		BSGS_AMP2 = malloc((uint64_t)((uint64_t)bsgs_m2*(uint64_t)sizeof(struct Point)));
		if(BSGS_AMP2 == NULL)	{
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
			printf("[+] Precalculating %"PRIu64" aMP points\n",bsgs_aux);
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


		mpz_set(point_temp.x,BSGS_MP2.x);
		mpz_set(point_temp.y,BSGS_MP2.y);
		for(i = 0; i < 20; i++)	{
			mpz_init(BSGS_AMP2[i].x);
			mpz_init(BSGS_AMP2[i].y);
			Point_Negation(&point_temp,&BSGS_AMP2[i]);
			Point_Addition(&point_temp,&BSGS_MP2,&point_temp2);
			mpz_set(point_temp.x,point_temp2.x);
			mpz_set(point_temp.y,point_temp2.y);
		}
		printf("[+] Allocating %.2f MB for %"PRIu64 " bP Points\n",(double)((double)((uint64_t)bsgs_m2*(uint64_t)sizeof(struct bsgs_xvalue))/(double)1048576),bsgs_m2);
		//printf("[+] Allocating %.2f MB for bP Points\n",(float)((uint64_t)((uint64_t)bsgs_m*(uint64_t)sizeof(struct bsgs_xvalue))/(uint64_t)1048576));
		bPtable = calloc(bsgs_m2,sizeof(struct bsgs_xvalue));
		if(bPtable == NULL)	{
			printf("[E] error malloc()\n");
			exit(0);
		}
		i = 0;
		j = 0;
		BASE = 0;
		PERTHREAD = bsgs_m /NTHREADS;
		PERTHREAD_R = bsgs_m % NTHREADS;
		temp = calloc(NTHREADS,sizeof(struct bPload));
		tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));

		if(FLAGPRECALCUTED_P_FILE)	{
			printf("[+] Reading %lu bP points from file %s\n",bsgs_m,precalculated_p_filename);
			for(i = 0; i < NTHREADS; i++)	{
				temp[i].counter = 0;
				if(i < NTHREADS -1)	{
					temp[i].from = BASE +1;
					temp[i].to = BASE + PERTHREAD;
				}
				else	{
					temp[i].from = BASE + 1;
					temp[i].to = BASE + PERTHREAD + PERTHREAD_R;
				}
				if(FLAGDEBUG) printf("[I] %lu to %lu\n",temp[i].from,temp[i].to);
				s = pthread_create(&tid[i],NULL,thread_bPloadFile,(void *)&temp[i]);
				BASE+=PERTHREAD;
			}
		}
		else	{
			for(i = 0; i < NTHREADS; i++)	{
				temp[i].counter = 0;
				if(i < NTHREADS -1)	{
					temp[i].from = BASE +1;
					temp[i].to = BASE + PERTHREAD;
				}
				else	{
					temp[i].from = BASE + 1;
					temp[i].to = BASE + PERTHREAD + PERTHREAD_R;
				}
				if(FLAGDEBUG) printf("[I] %lu to %lu\n",temp[i].from,temp[i].to);
				s = pthread_create(&tid[i],NULL,thread_bPload,(void *)&temp[i]);
				BASE+=PERTHREAD;
			}
		}
		total_precalculated = 0;
		do {
				sleep_ms(100);
				total_precalculated = 0;
				for(i = 0; i < NTHREADS; i++)	{
					total_precalculated+=temp[i].counter;
				}
				printf("\r[+] processing %lu/%lu bP points : %i%%",total_precalculated,bsgs_m,(int) (((double)total_precalculated/(double)bsgs_m)*100));
		} while(total_precalculated < bsgs_m);

		for(i = 0; i < NTHREADS; i++)	{
			pthread_join(tid[i], NULL);
		}
		printf("\n");
		free(temp);
		free(tid);

		printf("[+] Sorting %lu elements\n",bsgs_m2);
		bsgs_sort(bPtable,bsgs_m2);

		i = 0;

		steps = (unsigned int *) calloc(NTHREADS,sizeof(int));
		ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
		tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
		DEBUGCOUNT = (uint64_t)((uint64_t)bsgs_m * (uint64_t)bsgs_aux);
		for(i= 0;i < NTHREADS; i++)	{
			tt = malloc(sizeof(struct tothread));
			tt->nt = i;
			if(FLAGRANDOM)	{
				s = pthread_create(&tid[i],NULL,thread_process_bsgs_random,(void *)tt);
			}
			else	{
				s = pthread_create(&tid[i],NULL,thread_process_bsgs,(void *)tt);
			}

			if(s != 0)	{
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

		for(i= 0;i < NTHREADS; i++)	{
			tt = malloc(sizeof(struct tothread));
			tt->nt = i;
			steps[i] = 0;
			s = pthread_create(&tid[i],NULL,thread_process,(void *)tt);
			if(s != 0)	{
				fprintf(stderr,"[E] pthread_create thread_process\n");
				exit(0);
			}
		}

	}
	continue_flag = 1;
	mpz_init(total);
	mpz_init(pretotal);
	mpz_init(debugcount_mpz);
	sprintf(temporal,"%llu",(long long unsigned int)DEBUGCOUNT);
	mpz_set_str(debugcount_mpz,temporal,10);
	seconds = 0;
	do	{
		sleep(1);
		//c_beging = clock();
		seconds+=1;
		check_flag = 1;
		for(i = 0; i <NTHREADS && check_flag; i++) {
			check_flag &= ends[i];
		}
		if(check_flag)	{
			continue_flag = 0;
		}
		if(OUTPUTSECONDS > 0){
			if(seconds % OUTPUTSECONDS == 0) {
				mpz_set_ui(total,0);
				mpz_set_ui(pretotal,0);
				i = 0;
				while(i < NTHREADS) {
					mpz_mul_ui(pretotal,debugcount_mpz,steps[i]);
					mpz_add(total,total,pretotal);
					i++;
				}
				if(mpz_cmp_ui(total,0) > 0)	{
					mpz_fdiv_q_ui(pretotal,total,seconds);
					pthread_mutex_lock(&bsgs_thread);
					if(THREADOUTPUT == 1)	{
						gmp_sprintf(buffer,"\nTotal %Zu keys in %"PRIu64 " seconds: %Zu keys/s\r",total,seconds,pretotal);
					}
					else	{
						gmp_sprintf(buffer,"\rTotal %Zu keys in %"PRIu64" seconds: %Zu keys/s\r",total,seconds,pretotal);
					}
					printf("%s",buffer);
					fflush(stdout);
					THREADOUTPUT = 0;
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

void Point_Addition(struct Point *P, struct Point *Q, struct Point *R)	{
	mpz_t PA_temp,PA_slope;
	mpz_init(PA_temp);
	mpz_init(PA_slope);
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
					mpz_sub(R->x, R->x, Q->x);	//(c*c - A.x) -	B.x
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
	char *digest = calloc(60,1);
	size_t pubaddress_size = MAXLENGTHADDRESS+10;
	if(pubaddress == NULL || digest == NULL)	{
		fprintf(stderr,"error malloc()\n");
		exit(0);
	}
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

char *publickeytohashrmd160(char *pkey,int length)	{
	char *hash160 = malloc(20);
	char *digest = malloc(32);
	if(hash160 == NULL || digest == NULL)	{
		fprintf(stderr,"error malloc()\n");
		exit(0);
	}
	//digest [000...0]
 	sha256(pkey, length, digest);
	//digest [SHA256 32 bytes]
	RMD160Data((const unsigned char*)digest,32, hash160);
	//hash160 [RMD160 20 bytes]
	free(digest);
	return hash160;	// hash160 need to be free by te caller funtion
}


int searchbinary(struct address_value *buffer,char *data,int64_t _N) {
	int64_t half,min,max,current;
	int r = 0,rcmp;
	min = 0;
	current = 0;
	max = _N;
	half = _N;
	while(!r && half >= 1) {
		half = (max - min)/2;
		rcmp = memcmp(data,buffer[current+half].value,20);
		if(rcmp == 0)	{
			r = 1;	//Found!!
		}
		else	{
			if(rcmp < 0) { //data < temp_read
				max = (max-half);
			}
			else	{ // data > temp_read
				min = (min+half);
			}
			current = min;
		}
	}
	return r;
}

void *thread_process(void *vargp)	{
	struct tothread *tt;
	struct Point R,temporal;
	uint64_t count = 0;
	int r,thread_number,found,continue_flag = 1;
	char public_key_compressed[33],public_key_uncompressed[65],hexstrpoint[65];
	char *publickeyhashrmd160_compress,*publickeyhashrmd160_uncompress;
	char *hextemp,*public_key_compressed_hex,*public_key_uncompressed_hex;
	char *eth_address;
	char *public_address_compressed,*public_address_uncompressed;
	unsigned long longtemp;
	FILE *keys,*vanityKeys;
	mpz_t key_mpz,mpz_bit_range_min,mpz_bit_range_max,mpz_bit_range_diff;
	mpz_init(key_mpz);
	mpz_init(R.x);
	mpz_init(R.y);
	mpz_init(temporal.x);
	mpz_init(temporal.y);
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);

	found = 0;
	do {
		if(FLAGRANDOM){
			mpz_urandomm(key_mpz,state,n_range_diff);
			mpz_add(key_mpz,key_mpz,n_range_start);
		}
		else	{
			if(mpz_cmp(n_range_start,n_range_end) <= 0)	{
				pthread_mutex_lock(&write_random);
				mpz_set(key_mpz,n_range_start);
				mpz_add_ui(n_range_start,n_range_start,N_SECUENTIAL_MAX);
				pthread_mutex_unlock(&write_random);
			}
			else	{
				continue_flag = 0;
			}
		}
		if(continue_flag)	{
			if(FLAGQUIET == 0){
				gmp_sprintf(hexstrpoint,"%0.64Zx",key_mpz);
				printf("\rThread %i : Setting up base key: %s",thread_number,hexstrpoint);
				fflush(stdout);
				THREADOUTPUT = 1;
			}
			Scalar_Multiplication(G, &R, key_mpz);
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
				memcpy(public_key_uncompressed+1,public_key_compressed+1,32);
				gmp_sprintf(hexstrpoint,"%0.64Zx",R.y);
				hexs2bin(hexstrpoint,(unsigned char*)(public_key_uncompressed+33));

				switch(FLAGMODE)	{
					case MODE_ADDRESS:
						switch(FLAGSEARCH)	{
							case SEARCH_UNCOMPRESS:
								public_address_uncompressed = pubkeytopubaddress(public_key_uncompressed,65);
							break;
							case SEARCH_COMPRESS:
								public_address_compressed = pubkeytopubaddress(public_key_compressed,33);
							break;
							case SEARCH_BOTH:
								public_address_compressed = pubkeytopubaddress(public_key_compressed,33);
								public_address_uncompressed = pubkeytopubaddress(public_key_uncompressed,65);
							break;
						}
						if(FLAGVANITY)	{
							if(FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH){
								if(strncmp(public_address_uncompressed,vanity,len_vanity) == 0)	{
									hextemp = malloc(65);
									gmp_sprintf(hextemp,"%0.64Zx",key_mpz);
									vanityKeys = fopen("vanitykeys.txt","a+");
									if(vanityKeys != NULL)	{
										fprintf(vanityKeys,"PrivKey: %s\nAddress uncompressed: %s\n",hextemp,public_address_uncompressed);
										fclose(vanityKeys);
									}
									printf("\nVanity privKey: %s\nAddress uncompressed:	%s\n",hextemp,public_address_uncompressed);
									free(hextemp);
								}
							}
							if(FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH){
								if(strncmp(public_address_compressed,vanity,len_vanity) == 0)	{
									hextemp = malloc(65);
									gmp_sprintf(hextemp,"%0.64Zx",key_mpz);
									vanityKeys = fopen("vanitykeys.txt","a+");
									if(vanityKeys != NULL)	{
										fprintf(vanityKeys,"PrivKey: %s\nAddress compressed:	%s\n",hextemp,public_address_compressed);
										fclose(vanityKeys);
									}
									printf("\nVanity privKey: %s\nAddress compressed: %s\n",hextemp,public_address_compressed);
									free(hextemp);
								}
							}
						}
						if(FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH){
							r = bloom_check(&bloom,public_address_compressed,MAXLENGTHADDRESS);
							if(r) {
								r = searchbinary(addressTable,public_address_compressed,N);
								if(r) {
									found++;
									hextemp = malloc(65);
									gmp_sprintf(hextemp,"%0.64Zx",key_mpz);
									public_key_compressed_hex = tohex(public_key_compressed,33);
									pthread_mutex_lock(&write_keys);
									keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
									if(keys != NULL)	{
										fprintf(keys,"PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_compressed_hex,public_address_compressed);
										fclose(keys);
									}
									printf("\nHIT!! PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_compressed_hex,public_address_compressed);
									pthread_mutex_unlock(&write_keys);
									free(public_key_compressed_hex);
									free(hextemp);
								}
							}
							free(public_address_compressed);
						}

						if(FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH){
							r = bloom_check(&bloom,public_address_uncompressed,MAXLENGTHADDRESS);
							if(r) {
								r = searchbinary(addressTable,public_address_uncompressed,N);
								if(r) {
									found++;
									hextemp = malloc(65);
									gmp_sprintf(hextemp,"%0.64Zx",key_mpz);
									public_key_uncompressed_hex = tohex(public_key_uncompressed,65);
									pthread_mutex_lock(&write_keys);
									keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
									if(keys != NULL)	{
										fprintf(keys,"PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_uncompressed_hex,public_address_uncompressed);
										fclose(keys);
									}
									printf("\nHIT!! PrivKey: %s\npubkey: %s\naddress: %s\n",hextemp,public_key_uncompressed_hex,public_address_uncompressed);
									pthread_mutex_unlock(&write_keys);
									free(public_key_uncompressed_hex);
									free(hextemp);
								}
							}
							free(public_address_uncompressed);
						}
						if( (FLAGCRYPTO & CRYPTO_ETH) != 0) {
							/*
							mpz_export((public_key_uncompressed+1),&longtemp,1,8,1,0,R.x);
							mpz_export((public_key_uncompressed+33),&longtemp,1,8,1,0,R.y);
							public_address_uncompressed = pubkeytopubaddress_eth(public_key_uncompressed+1,64);
							//printf("Testing for %s\n",public_address_uncompressed);
							r = bloom_check(&bloom,public_address_uncompressed,MAXLENGTHADDRESS);
							if(r) {
								r = searchbinary(addressTable,public_address_uncompressed,N);
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
					break;
					case MODE_RMD160:
						switch(FLAGSEARCH)	{
							case SEARCH_UNCOMPRESS:
								publickeyhashrmd160_uncompress = publickeytohashrmd160(public_key_uncompressed,65);
							break;
							case SEARCH_COMPRESS:
								publickeyhashrmd160_compress = publickeytohashrmd160(public_key_compressed,33);
							break;
							case SEARCH_BOTH:
								publickeyhashrmd160_compress = publickeytohashrmd160(public_key_compressed,33);
								publickeyhashrmd160_uncompress = publickeytohashrmd160(public_key_uncompressed,65);
							break;
						}

						if(FLAGSEARCH == SEARCH_COMPRESS || FLAGSEARCH == SEARCH_BOTH){
							r = bloom_check(&bloom,publickeyhashrmd160_compress,MAXLENGTHADDRESS);
							if(r) {
								r = searchbinary(addressTable,publickeyhashrmd160_compress,N);
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
									printf("\nHIT!! PrivKey: %s\npubkey: %s\n",hextemp,public_key_compressed_hex);
									pthread_mutex_unlock(&write_keys);
									free(public_key_compressed_hex);
									free(hextemp);
								}
							}
							free(publickeyhashrmd160_compress);
						}
						if(FLAGSEARCH == SEARCH_UNCOMPRESS || FLAGSEARCH == SEARCH_BOTH){
							r = bloom_check(&bloom,publickeyhashrmd160_uncompress,MAXLENGTHADDRESS);
							if(r) {
								r = searchbinary(addressTable,publickeyhashrmd160_uncompress,N);
								if(r) {
									found++;
									hextemp = malloc(65);
									gmp_sprintf(hextemp,"%0.64Zx",key_mpz);
									public_key_uncompressed_hex = tohex(public_key_uncompressed,65);
									pthread_mutex_lock(&write_keys);
									keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
									if(keys != NULL)	{
										fprintf(keys,"PrivKey: %s\npubkey: %s\n",hextemp,public_key_uncompressed_hex);
										fclose(keys);
									}
									printf("\nHIT!! PrivKey: %s\npubkey: %s\n",hextemp,public_key_uncompressed_hex);
									pthread_mutex_unlock(&write_keys);
									free(public_key_uncompressed_hex);
									free(hextemp);
								}
							}
							free(publickeyhashrmd160_uncompress);
						}
					break;
					case MODE_XPOINT:
						r = bloom_check(&bloom,public_key_compressed+1,MAXLENGTHADDRESS);
						if(r) {
							r = searchbinary(addressTable,public_key_compressed+1,N);
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
								printf("\nHIT!! PrivKey: %s\npubkey: %s\n",hextemp,public_key_compressed_hex);
								pthread_mutex_unlock(&write_keys);
								free(public_key_compressed_hex);
								free(hextemp);
							}
						}
					break;
				}
				count++;
				if(count %	DEBUGCOUNT == 0)	{
					steps[thread_number]++;
				}
				mpz_add_ui(key_mpz,key_mpz,1);
				Point_Addition(&temporal,&G,&R);
			}while(count <= N_SECUENTIAL_MAX);
		}
	} while(continue_flag);
	printf("Found %i\n",found);
	ends[thread_number] = 1;
	return NULL;
}

void _swap(struct address_value *a,struct address_value *b)	{
	struct address_value t;
	t  = *a;
	*a = *b;
	*b =  t;
}

void _sort(struct address_value *arr,int64_t n)	{
	uint32_t depthLimit = ((uint32_t) ceil(log(n))) * 2;
	_introsort(arr,depthLimit,n);
}

void _introsort(struct address_value *arr,uint32_t depthLimit, int64_t n) {
	int64_t p;
	if(n > 1)	{
		if(n <= 16) {
			_insertionsort(arr,n);
		}
		else	{
			if(depthLimit == 0) {
				_myheapsort(arr,n);
			}
			else	{
				p = _partition(arr,n);
				if(p > 0) _introsort(arr , depthLimit-1 , p);
				if(p < n) _introsort(&arr[p+1],depthLimit-1,n-(p+1));
			}
		}
	}
}

void _insertionsort(struct address_value *arr, int64_t n) {
	int64_t j;
	int64_t i;
	struct address_value key;
	for(i = 1; i < n ; i++ ) {
		key = arr[i];
		j= i-1;
		while(j >= 0 && memcmp(arr[j].value,key.value,20) > 0) {
			arr[j+1] = arr[j];
			j--;
		}
		arr[j+1] = key;
	}
}

int64_t _partition(struct address_value *arr, int64_t n)	{
	struct address_value pivot;
	int64_t r,left,right;
	char *hextemp;
	r = n/2;
	pivot = arr[r];
	left = 0;
	right = n-1;
	do {
		while(left	< right && memcmp(arr[left].value,pivot.value,20) <= 0 )	{
			left++;
		}
		while(right >= left && memcmp(arr[right].value,pivot.value,20) > 0)	{
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
			_swap(&arr[right],&arr[left]);
		}
	}while(left < right);
	if(right != r)	{
		_swap(&arr[right],&arr[r]);
	}
	return right;
}

void _heapify(struct address_value *arr, int64_t n, int64_t i) {
	int64_t largest = i;
	int64_t l = 2 * i + 1;
	int64_t r = 2 * i + 2;
	if (l < n && memcmp(arr[l].value,arr[largest].value,20) > 0)
		largest = l;
	if (r < n && memcmp(arr[r].value,arr[largest].value,20) > 0)
		largest = r;
	if (largest != i) {
		_swap(&arr[i],&arr[largest]);
		_heapify(arr, n, largest);
	}
}

void _myheapsort(struct address_value	*arr, int64_t n)	{
	int64_t i;
	for ( i = (n / 2) - 1; i >=	0; i--)	{
		_heapify(arr, n, i);
	}
	for ( i = n - 1; i > 0; i--) {
		_swap(&arr[0] , &arr[i]);
		_heapify(arr, i, 0);
	}
}

/*	OK	*/
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b)	{
	struct bsgs_xvalue t;
	t	= *a;
	*a = *b;
	*b =	t;
}

/*	OK	*/
void bsgs_sort(struct bsgs_xvalue *arr,int64_t n)	{
	uint32_t depthLimit = ((uint32_t) ceil(log(n))) * 2;
	bsgs_introsort(arr,depthLimit,n);
}

/*	OK	*/
void bsgs_introsort(struct bsgs_xvalue *arr,uint32_t depthLimit, int64_t n) {
	int64_t p;
	if(n > 1)	{
		if(n <= 16) {
			bsgs_insertionsort(arr,n);
		}
		else	{
			if(depthLimit == 0) {
				bsgs_myheapsort(arr,n);
			}
			else	{
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

int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n)	{
	struct bsgs_xvalue pivot;
	int64_t r,left,right;
	char *hextemp;
	r = n/2;
	pivot = arr[r];
	left = 0;
	right = n-1;
	do {
		while(left	< right && memcmp(arr[left].value,pivot.value,BSGS_XVALUE_RAM) <= 0 )	{
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

void bsgs_myheapsort(struct bsgs_xvalue	*arr, int64_t n)	{
	int64_t i;
	for ( i = (n / 2) - 1; i >=	0; i--)	{
		bsgs_heapify(arr, n, i);
	}
	for ( i = n - 1; i > 0; i--) {
		bsgs_swap(&arr[0] , &arr[i]);
		bsgs_heapify(arr, i, 0);
	}
}

int bsgs_searchbinary(struct bsgs_xvalue *buffer,char *data,int64_t _N,uint64_t *r_value) {
	char *temp_read;
	int64_t min,max,half,current;
	int r = 0,rcmp;
	min = 0;
	current = 0;
	max = _N;
	half = _N;
	while(!r && half >= 1) {
		half = (max - min)/2;
		rcmp = memcmp(data+16,buffer[current+half].value,BSGS_XVALUE_RAM);
		if(rcmp == 0)	{
			*r_value = buffer[current+half].index;
			r = 1;
		}
		else	{
			if(rcmp < 0) {
				max = (max-half);
			}
			else	{
				min = (min+half);
			}
			current = min;
		}
	}
	return r;
}

void *thread_process_bsgs(void *vargp)	{
	struct tothread *tt;
	char pubkey[131],xpoint_str[65],xpoint_raw[32];
	char *aux_c;
	mpz_t base_key,keyfound;
	FILE *filekey;
	struct Point base_point,point_aux,point_aux2,point_found,BSGS_S,BSGS_Q,BSGS_Q_AMP;
	uint32_t i,j,k,r,salir,thread_number,bloom_counter =0;
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

	mpz_init(BSGS_S.x);
	mpz_init(BSGS_S.y);
	mpz_init(BSGS_Q.x);
	mpz_init(BSGS_Q.y);



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
		if(FLAGQUIET == 0){
			gmp_sprintf(xpoint_str,"%0.64Zx",base_key);
			printf("\r[+] Thread %i: %s",thread_number,xpoint_str);
			fflush(stdout);
			THREADOUTPUT = 1;
		}
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

		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
				/*reset main variabler before the do-while cicle*/
				/* Main cycle
					for every a in 0 to bsgs_m
				*/
				salir = 0;
				i = 0;
				Point_Addition(&OriginalPointsBSGS[k],&point_aux,&BSGS_Q);
				mpz_set(BSGS_S.x,BSGS_Q.x);
				mpz_set(BSGS_S.y,BSGS_Q.y);

				do {
					/* We need to test individually every point in BSGS_Q */
					/*Extract BSGS_S.x into xpoint_str*/
					gmp_sprintf(xpoint_str,"%0.64Zx",BSGS_S.x);
					/*xpoint_str -> binary*/
					hexs2bin(xpoint_str,(unsigned char*)xpoint_raw);
					//printf("Looking X : %s\n",xpoint_str);
					/* Lookup for the xpoint_raw into the bloom filter*/

					r = custombloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])],xpoint_raw,32);
					if(r) {
						bloom_counter++;
						/* Lookup for the xpoint_raw into the full sorted list*/
						//r = bsgs_searchbinary(bPtable,xpoint_raw,bsgs_m,&j);
						r = bsgs_secondcheck(base_key,i,&OriginalPointsBSGS[k],&keyfound);

						if(r)	{
							gmp_sprintf(xpoint_str,"%0.64Zx",keyfound);
							printf("\n[+] Thread %i Key found privkey %s\n",thread_number,xpoint_str);
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
					}
					Point_Addition(&BSGS_Q,&BSGS_AMP[i],&BSGS_Q_AMP);
					mpz_set(BSGS_S.x,BSGS_Q_AMP.x);
					mpz_set(BSGS_S.y,BSGS_Q_AMP.y);
					i++;
				}while( i < bsgs_aux && !bsgs_found[k]);
			} //end if
		}// End for
		steps[thread_number]++;
		pthread_mutex_lock(&bsgs_thread);
		mpz_set(base_key,BSGS_CURRENT);
		mpz_add(BSGS_CURRENT,BSGS_CURRENT,BSGS_N);
		pthread_mutex_unlock(&bsgs_thread);
		if(FLAGDEBUG ) printf("%u of %"PRIu64"\n",bloom_counter,(uint64_t)(bsgs_aux*bsgs_point_number));
		bloom_counter = 0;
	}

	mpz_clear(BSGS_Q.x);
	mpz_clear(BSGS_Q.y);
	mpz_clear(BSGS_S.x);
	mpz_clear(BSGS_S.y);

	mpz_clear(base_key);
	mpz_clear(keyfound);
	mpz_clear(base_point.x);
	mpz_clear(base_point.y);
	mpz_clear(point_aux.x);
	mpz_clear(point_aux.y);
	mpz_clear(point_aux2.x);
	mpz_clear(point_aux2.y);
	ends[thread_number] = 1;
	return NULL;
}

void *thread_process_bsgs_random(void *vargp)	{
	struct tothread *tt;
	char pubkey[131],xpoint_str[65],xpoint_raw[32];
	char *aux_c;
	mpz_t base_key,keyfound;
	FILE *filekey;
	struct Point base_point,point_aux,point_aux2,point_found,BSGS_S,BSGS_Q,BSGS_Q_AMP;
	mpz_t n_range_random;
	uint32_t i,j,k,r,salir,thread_number,bloom_counter = 0;
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


	mpz_init(BSGS_S.x);
	mpz_init(BSGS_S.y);
	mpz_init(BSGS_Q.x);
	mpz_init(BSGS_Q.y);

	pthread_mutex_lock(&bsgs_thread);
	/*			| Start Range	 | End Range		|
		None	| 1							|	EC.N				 |
-b	bit		| Min bit value |Max bit value |
-r	A:B	 | A						 | B 					 |
	*/
	// set n_range_random = random(end_range - start range)
	mpz_urandomm (n_range_random,state,n_range_diff);

	// base key =	start + random value
	mpz_add(base_key,n_range_start,n_range_random);
	pthread_mutex_unlock(&bsgs_thread);
	/*
		while base_key is less than n_range_end then:
	*/
	while(mpz_cmp(base_key,n_range_end) < 0)	{
		//gmp_printf("While cycle: base_key : %Zd < n_range_end: %Zd\n",base_key,n_range_end);
		if(FLAGQUIET == 0){
			gmp_sprintf(xpoint_str,"%0.64Zx",base_key);
			printf("\r[+] Thread %i: %s",thread_number,xpoint_str);
			fflush(stdout);
			THREADOUTPUT = 1;
		}
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


		/* We need to test individually every point in BSGS_Q */
		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
			/*reset main variabler before the do-while cicle*/
			salir = 0;
			i = 0;
			/* Main cycle for every a in 0 to bsgs_aux
			*/
			Point_Addition(&OriginalPointsBSGS[k],&point_aux,&BSGS_Q);
			mpz_set(BSGS_S.x,BSGS_Q.x);
			mpz_set(BSGS_S.y,BSGS_Q.y);
			do {
					gmp_sprintf(xpoint_str,"%0.64Zx",BSGS_S.x);
					hexs2bin(xpoint_str,(unsigned char*)xpoint_raw);

					r = custombloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])],xpoint_raw,32);
					if(r) {
						bloom_counter++;
						/* Lookup for the xpoint_raw into the full sorted list*/
						r = bsgs_secondcheck(base_key,i,&OriginalPointsBSGS[k],&keyfound);
						if(r)	{
							gmp_sprintf(xpoint_str,"%0.64Zx",keyfound);
							printf("\n[+] Thread %i Key found privkey %s\n",thread_number,xpoint_str);
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
					}
					Point_Addition(&BSGS_Q,&BSGS_AMP[i],&BSGS_Q_AMP);
					mpz_set(BSGS_S.x,BSGS_Q_AMP.x);
					mpz_set(BSGS_S.y,BSGS_Q_AMP.y);
					i++;
				} while( i < bsgs_aux && !bsgs_found[k]);
			}	//End if
		} // End for with k bsgs_point_number
		steps[thread_number]++;
		pthread_mutex_lock(&bsgs_thread);
		mpz_urandomm (n_range_random,state,n_range_diff);
		mpz_add(base_key,n_range_start,n_range_random);
		pthread_mutex_unlock(&bsgs_thread);
		if(FLAGDEBUG ) printf("%u of %"PRIu64"\n",bloom_counter,(uint64_t)(bsgs_aux*bsgs_point_number));
		bloom_counter = 0;
	}
	mpz_clear(BSGS_Q.x);
	mpz_clear(BSGS_Q.y);
	mpz_clear(BSGS_S.x);
	mpz_clear(BSGS_S.y);

	mpz_clear(base_key);
	mpz_clear(keyfound);
	mpz_clear(base_point.x);
	mpz_clear(base_point.y);
	mpz_clear(point_aux.x);
	mpz_clear(point_aux.y);
	mpz_clear(point_aux2.x);
	mpz_clear(point_aux2.y);
	ends[thread_number] = 1;
	return NULL;
}


/*
	The bsgs_secondcheck function is made to perform a second BSGS search in a Range of less size.
	This funtion is made with the especific purpouse to USE a smaller bPTable in RAM.
	This new and small bPtable is around ~ squareroot( K *squareroot(N))
*/
int bsgs_secondcheck(mpz_t start_range,uint32_t a,struct Point *target,mpz_t *private)	{
	uint64_t j = 0;
	int i = 0,found = 0,r = 0;
	mpz_t base_key;
	struct Point base_point,point_aux;
	struct Point BSGS_Q, BSGS_S,BSGS_Q_AMP;
	char pubkey[131],xpoint_str[65],xpoint_raw[32];

	mpz_init(base_key);
	mpz_init(base_point.x);
	mpz_init(base_point.y);
	mpz_init(BSGS_Q.x);
	mpz_init(BSGS_Q.y);
	mpz_init(BSGS_S.x);
	mpz_init(BSGS_S.y);
	mpz_init(BSGS_Q_AMP.y);
	mpz_init(BSGS_Q_AMP.x);
	mpz_init(point_aux.y);
	mpz_init(point_aux.x);


	mpz_mul_ui(base_key,BSGS_M,a);
	mpz_add(base_key,base_key,start_range);

	Scalar_Multiplication(G,&base_point,base_key);
	Point_Negation(&base_point,&point_aux);
	Point_Addition(target,&point_aux,&BSGS_S);

	mpz_set(BSGS_Q.x,BSGS_S.x);
	mpz_set(BSGS_Q.y,BSGS_S.y);

	//gmp_printf("bsgs_secondcheck\nBase key %0.64Zx\nM2 %Zu\n",base_key,BSGS_M2);
	do {
		gmp_sprintf(xpoint_str,"%0.64Zx",BSGS_S.x);
		hexs2bin(xpoint_str,(unsigned char*)xpoint_raw);
		r = custombloom_check(&bloom_bPx2nd,xpoint_raw,32);
		if(r)	{
			//printf("bloom_bPx2nd MAYBE!!\n");
			/* Lookup for the xpoint_raw into the full sorted list*/
			r = bsgs_searchbinary(bPtable,xpoint_raw,bsgs_m2,&j);
			//printf("bsgs_searchbinary: %s\n",r ? "yes":"no");
			//printf("Current i: %u j: %llu, m: %llu\n",i,j,bsgs_m2);
			if(r)	{
				mpz_set(*private,BSGS_M2);
				mpz_mul_ui(*private,*private,i);
				mpz_add_ui(*private,*private,j+1);
				mpz_add(*private,*private,base_key);
				Scalar_Multiplication(G,&point_aux,*private);
				//gmp_printf("private 1: %0.64Zx\n",*private);
				if(mpz_cmp(point_aux.x,target->x) == 0)	{
					found = 1;
				}
				else	{
					mpz_set(*private,BSGS_M2);
					mpz_mul_ui(*private,*private,i);
					mpz_sub_ui(*private,*private,j+1);
					mpz_add(*private,*private,base_key);
					//gmp_printf("private 2: %0.64Zx\n",*private);
					if(mpz_cmp(point_aux.x,target->x) == 0)	{
						found = 1;
					}
				}
			}
		}
		Point_Addition(&BSGS_Q,&BSGS_AMP2[i],&BSGS_Q_AMP);
		mpz_set(BSGS_S.x,BSGS_Q_AMP.x);
		mpz_set(BSGS_S.y,BSGS_Q_AMP.y);
		i++;
	}while(i < 20 && !found);

	mpz_clear(base_key);
	mpz_clear(base_point.x);
	mpz_clear(base_point.y);
	mpz_clear(BSGS_Q.x);
	mpz_clear(BSGS_Q.y);
	mpz_clear(BSGS_S.x);
	mpz_clear(BSGS_S.y);
	mpz_clear(BSGS_Q_AMP.y);
	mpz_clear(BSGS_Q_AMP.x);
	mpz_clear(point_aux.y);
	mpz_clear(point_aux.x);
	return found;
}

void *thread_bPload(void *vargp)	{
	char hexvalue[65],rawvalue[32];
	struct bPload *tt;
	struct Point P,temp;
	mpz_t base;
	uint32_t j;
	uint64_t i;
	tt = (struct bPload *)vargp;
	mpz_init(base);
	mpz_init(P.x);
	mpz_init(P.y);
	mpz_init(temp.x);
	mpz_init(temp.y);
	mpz_set_ui(base,tt->from);
	Scalar_Multiplication(G,&P,base);
	i = tt->from -1;
	j = tt->from -1;
	do {
		mpz_set(temp.x,P.x);
		mpz_set(temp.y,P.y);
		gmp_sprintf(hexvalue,"%0.64Zx",P.x);
		hexs2bin(hexvalue,(unsigned char*) rawvalue );
		if(i < bsgs_m2)	{
			memcpy(bPtable[j].value,rawvalue+16,BSGS_XVALUE_RAM);
			bPtable[j].index = j;
			custombloom_add(&bloom_bPx2nd, rawvalue, BSGS_BUFFERXPOINTLENGTH);
			j++;
		}
		custombloom_add(&bloom_bP[((uint8_t)rawvalue[0])], rawvalue ,BSGS_BUFFERXPOINTLENGTH);
		Point_Addition(&G,&temp,&P);
		i++;
		tt->counter++;
	} while( i < tt->to );
	mpz_clear(base);
	mpz_clear(P.x);
	mpz_clear(P.y);
	mpz_clear(temp.x);
	mpz_clear(temp.y);
	pthread_exit(NULL);
}

void *thread_bPloadFile(void *vargp)	{
	FILE *fd;
	char rawvalue[32];
	struct bPload *tt;

	uint32_t j;
	uint64_t i;
	tt = (struct bPload *)vargp;
	fd = fopen(precalculated_p_filename,"rb");
	if(fd == NULL)	{
		fprintf(stderr,"Can't open file\n");
		exit(0);
	}
	i = tt->from -1;
	j = tt->from -1;
	if(fseek(fd,i*32,SEEK_SET) != 0)	{
		fprintf(stderr,"Can't seek the file\n");
		exit(0);
	}
	do {
		if(fread(rawvalue,1,32,fd) == 32)	{
			if(i < bsgs_m2)	{
				memcpy(bPtable[j].value,rawvalue+16,BSGS_XVALUE_RAM);
				bPtable[j].index = j;
				custombloom_add(&bloom_bPx2nd, rawvalue, BSGS_BUFFERXPOINTLENGTH);
				j++;
			}
			custombloom_add(&bloom_bP[((uint8_t)rawvalue[0])], rawvalue ,BSGS_BUFFERXPOINTLENGTH);
			i++;
			tt->counter++;
		}
		else	{
			fprintf(stderr,"Can't read the file seen you have less items that the amount needed\n");
			exit(0);
		}
	} while( i < tt->to );
	pthread_exit(NULL);
}

void sleep_ms(int milliseconds)	{ // cross-platform sleep function
#ifdef WIN32
    Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
#else
    if (milliseconds >= 1000)
      sleep(milliseconds / 1000);
    usleep((milliseconds % 1000) * 1000);
#endif
}
