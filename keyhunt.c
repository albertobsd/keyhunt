/*
Develop by Luis Alberto
email: alberto.bsd@gmail.com

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "sha256/sha256.h"
#include "bloom/bloom.h"
#include "sha3/sha3.h"

#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "secp256k1/Random.h"

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
#define MODE_PUB2RMD 4


#define SEARCH_UNCOMPRESS 0
#define SEARCH_COMPRESS 1
#define SEARCH_BOTH 2


struct bsgs_xvalue	{
	uint8_t value[6];
	uint64_t index;
};

struct address_value	{
	uint8_t value[20];
};

struct tothread {
	int nt;     //Number thread
	char *rs;   //range start
	char *rpt;  //rng per thread
};

struct bPload	{
	uint32_t threadid;
	uint64_t from;
	uint64_t to;
	uint64_t counter;
};

struct __attribute__((__packed__)) publickey {
  uint8_t parity;
	union	{
		uint8_t data8[32];
		uint32_t data32[8];
		uint64_t data64[4];
	} X;
};

const char *version = "0.2.211007 Chocolate ¡Beta!";

#define CPU_GRP_SIZE 1024

std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;

void init_generator();


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
int bsgs_secondcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey);

void *thread_process(void *vargp);
void *thread_process_bsgs(void *vargp);
void *thread_process_bsgs_backward(void *vargp);
void *thread_process_bsgs_both(void *vargp);
void *thread_process_bsgs_random(void *vargp);
void *thread_process_bsgs_dance(void *vargp);
void *thread_bPload(void *vargp);
void *thread_bPloadFile(void *vargp);
void *thread_pub2rmd(void *vargp);

char *publickeytohashrmd160(char *pkey,int length);
char *pubkeytopubaddress(char *pkey,int length);

void KECCAK_256(uint8_t *source, size_t size,uint8_t *dst);
void generate_binaddress_eth(Point *publickey,unsigned char *dst_address);

void memorycheck();

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *bsgs_modes[5] {"secuential","backward","both","random","dance"};
const char *modes[5] = {"xpoint","address","bsgs","rmd160","pub2rmd"};
const char *cryptos[3] = {"btc","eth","all"};
const char *publicsearch[3] = {"uncompress","compress","both"};
const char *default_filename = "addresses.txt";

pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;

pthread_mutex_t bsgs_thread;

struct bloom bloom;


uint64_t *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;


uint64_t N_SECUENTIAL_MAX = 0xffffffff;
uint64_t DEBUGCOUNT = 0x100000;




Int OUTPUTSECONDS;


int FLAGBSGSMODE = 0;
int FLAGDEBUG = 0;
int FLAGQUIET = 0;
int FLAGMATRIX = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;

int FLAGSAVEREADFILE = 0;
int FLAGREADEDFILE1 = 0;
int FLAGREADEDFILE2 = 0;
int FLAGREADEDFILE3 = 0;
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

int len_vanity;
int bitrange;
char *str_N;
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
std::vector<Point> OriginalPointsBSGS;
bool *OriginalPointsBSGScompressed;

uint64_t bytes;
char checksum[32],checksum_backup[32];
char buffer_bloom_file[1024];
struct bsgs_xvalue *bPtable;
struct address_value *addressTable;
struct bloom bloom_bP;
struct bloom bloom_bPx2nd; //Second Bloom filter check
uint64_t bloom_bP_totalbytes = 0;
char *precalculated_p_filename;
uint64_t bsgs_m = 4194304;
uint64_t bsgs_m2;

unsigned long int bsgs_aux;
uint32_t bsgs_point_number;

const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[6];




Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX;
Int BSGS_N;
Int BSGS_M;					//M is squareroot(N)
Int BSGS_M2;
Int ONE;
Int ZERO;
Int MPZAUX;

Point BSGS_P;			//Original P is actually G, but this P value change over time for calculations
Point BSGS_MP;			//MP values this is m * P
Point BSGS_MP2;			//MP values this is m2 * P

std::vector<Point> BSGS_AMP2;

Point point_temp,point_temp2;	//Temp value for some process

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;

Secp256K1 *secp;

int main(int argc, char **argv)	{
	char buffer[2048];
	char temporal[65];
	char rawvalue[32];
	struct tothread *tt;	//tothread
	Tokenizer t,tokenizerbsgs,tokenizer_xpoint;	//tokenizer
	char *filename,*precalculated_mp_filename,*hextemp,*aux,*aux2,*pointx_str,*pointy_str,*str_seconds,*str_total,*str_pretotal,*str_divpretotal,*bf_ptr;
	FILE *fd,*fd_aux1,*fd_aux2,*fd_aux3;
	uint64_t j,total_precalculated,i,PERTHREAD,BASE,PERTHREAD_R;
	int readed,s,continue_flag,check_flag,r,lenaux,lendiff,c,salir,index_value;
	Int total,pretotal,debugcount_mpz,seconds,div_pretotal;
	struct bPload *temp;
	srand (time(NULL));

	secp = new Secp256K1();
	secp->Init();
	OUTPUTSECONDS.SetInt32(30);
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);
	rseed(clock() + time(NULL));

	printf("[+] Version %s, developed by AlbertoBSD\n",version);

	while ((c = getopt(argc, argv, "dehMqRwzSB:b:c:E:f:k:l:m:n:p:r:s:t:v:G:")) != -1) {
		switch(c) {
			case 'h':
				printf("\nUsage:\n-h\t\tshow this help\n");
				printf("-B Mode\t\tBSGS now have some modes <secuential,backward,both,random,dance>\n");
				printf("-b bits\t\tFor some puzzles you only need some numbers of bits in the test keys.\n");
				printf("\t\tThis option only is valid with the Random option -R\n");
				printf("-c crypto\tSearch for specific crypo. < btc, eth, all > valid only w/ -m address \n");
				printf("\t\tYour file MUST be sordted if no you are going to lose collisions\n");
				printf("-f file\t\tSpecify filename with addresses or xpoints or uncompressed public keys\n");
				printf("-g count\tJust for the stats, mark as counted every debugcount keys	\n");
				printf("-k value\tUse this only with bsgs mode, k value is factor for M, more speed but more RAM use wisely\n");
				printf("-l look\tWhat type of address/hash160 are you looking for < compress , uncompress , both>\n");
				printf("-m mode\t\tmode of search for cryptos. ( bsgs , xpoint , rmd160 , address ) default: address (more slow)\n");
				printf("-M\t\tMatrix screen, feel like a h4x0r, but performance will droped\n");
				printf("-n uptoN\tCheck for N secuential numbers before the random chossen this only work with -R option\n");
				printf("\t\tUse -n to set the N for the BSGS process. Bigger N more RAM needed\n");
				printf("-p file\t\tfile is a binary raw file with the bP points precalculated. Just work with -m bsgs\n");
				printf("-q\t\tQuiet the thread output\n");
				printf("-r SR:EN\tStarRange:EndRange, the end range can be omited for search from start range to N-1 ECC value\n");
				printf("-R\t\tRandom this is the default behaivor\n");
				printf("-s ns\t\tNumber of seconds for the stats output, 0 to omit output.\n");
				printf("-S\t\tCapital S is for SAVING in files BSGS data (Bloom filters and bPtable)\n");
				printf("-t tn\t\tThreads number, must be positive integer\n");
				printf("-v va\t\tSearch for vanity Address, only with -m address\n");
				printf("-w\t\tMark the input file as RAW data xpoint fixed 32 byte each point. Valid only with -m xpoint\n");
				printf("\nExample\n\n");
				printf("%s -t 16 -r 1:FFFFFFFF -s 0\n\n",argv[0]);
				printf("This line run the program with 16 threads from the range 1 to FFFFFFFF without stats output\n\n");
				printf("Developed by AlbertoBSD\tTips BTC: 1ABSD1rMTmNZHJrJP8AJhDNG1XbQjWcRz7\n");
				printf("Thanks to Iceland always helping and sharing his ideas.\nTips to Iceland: bc1q39meky2mn5qjq704zz0nnkl0v7kj4uz6r529at\n\n");
				exit(0);
			break;
			case 'B':
				index_value = indexOf(optarg,bsgs_modes,5);
				if(index_value >= 0 && index_value <= 4)	{
					FLAGBSGSMODE = index_value;
					//printf("[+] BSGS mode %s\n",optarg);
				}
				else	{
					fprintf(stderr,"[W] Ignoring unknow bsgs mode %s\n",optarg);
				}
			break;
			case 'b':
				bitrange = strtol(optarg,NULL,10);
				if(bitrange > 0 && bitrange <=256 )	{
					MPZAUX.Set(&ONE);
					MPZAUX.ShiftL(bitrange-1);
					bit_range_str_min = MPZAUX.GetBase16();
					MPZAUX.Set(&ONE);
					MPZAUX.ShiftL(bitrange);
					if(MPZAUX.IsGreater(&secp->order))	{
						MPZAUX.Set(&secp->order);
					}
					bit_range_str_max = MPZAUX.GetBase16();
					if(bit_range_str_min == NULL||bit_range_str_max == NULL)	{
						fprintf(stderr,"[E] error malloc()\n");
						exit(0);
					}
					FLAGBITRANGE = 1;
				}
				else	{
					fprintf(stderr,"[E] invalid bits param: %s.\n",optarg);
				}
			break;
			case 'c':
				index_value = indexOf(optarg,cryptos,3);
				switch(index_value) {
					case 0: //btc
						FLAGCRYPTO = CRYPTO_BTC;
						printf("[+] Setting search for BTC adddress.\n");
					break;
					case 1: //eth
						FLAGCRYPTO = CRYPTO_ETH;
						printf("[+] Setting search for ETH adddress.\n");
					break;
					case 2: //all
						FLAGCRYPTO = CRYPTO_ALL;
						printf("[+] Setting search for all cryptocurrencies avaible [btc].\n");
					break;
					default:
						FLAGCRYPTO = CRYPTO_NONE;
						fprintf(stderr,"[E] Unknow crypto value %s\n",optarg);
						exit(0);
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

			case 'k':
				KFACTOR = (int)strtol(optarg,NULL,10);
				if(KFACTOR <= 0)	{
					KFACTOR = 1;
				}
				printf("[+] K factor %i\n",KFACTOR);
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
			case 'M':
				FLAGMATRIX = 1;
				printf("[+] Matrix screen\n");
			break;
			case 'm':
				switch(indexOf(optarg,modes,5)) {
					case MODE_XPOINT: //xpoint
						FLAGMODE = MODE_XPOINT;
						printf("[+] Mode xpoint\n");
					break;
					case MODE_ADDRESS: //address
						FLAGMODE = MODE_ADDRESS;
						printf("[+] Mode address\n");
					break;
					case MODE_BSGS:
						FLAGMODE = MODE_BSGS;
						//printf("[+] Mode BSGS\n");
					break;
					case MODE_RMD160:
						FLAGMODE = MODE_RMD160;
						printf("[+] Mode rmd160\n");
					break;
					case MODE_PUB2RMD:
						FLAGMODE = MODE_PUB2RMD;
						printf("[+] Mode pub2rmd\n");
					break;
					default:
						fprintf(stderr,"[E] Unknow mode value %s\n",optarg);
						exit(0);
					break;
				}
			break;
			case 'n':
				FLAG_N = 1;
				str_N = optarg;
			break;
			case 'q':
				FLAGQUIET	= 1;
				printf("[+] Quiet thread output\n");
			break;
			case 'p':
				FLAGPRECALCUTED_P_FILE = 1;
				precalculated_p_filename = optarg;
			break;
			case 'R':
				printf("[+] Random mode\n");
				FLAGRANDOM = 1;
				FLAGBSGSMODE =  3;
			break;
			case 'r':
				if(optarg != NULL)	{
					stringtokenizer(optarg,&t);
					switch(t.n)	{
						case 1:
							range_start = nextToken(&t);
							if(isValidHex(range_start)) {
								FLAGRANGE = 1;
								range_end = secp->order.GetBase16();
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
				OUTPUTSECONDS.SetBase10(optarg);
				if(OUTPUTSECONDS.IsLower(&ZERO))	{
					OUTPUTSECONDS.SetInt32(30);
				}
				if(OUTPUTSECONDS.IsZero())	{
					printf("[+] Turn off stats output\n");
				}
				else	{
					hextemp = OUTPUTSECONDS.GetBase10();
					printf("[+] Stats output every %s seconds\n",hextemp);
					free(hextemp);
				}
			break;
			case 'S':
				FLAGSAVEREADFILE = 1;
			break;
			case 't':
				NTHREADS = strtol(optarg,NULL,10);
				if(NTHREADS <= 0)	{
					NTHREADS = 1;
				}
				printf((NTHREADS > 1) ? "[+] Threads : %u\n": "[+] Thread : %u\n",NTHREADS);
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
				printf("[E] Unknow opcion -%c\n",c);
			break;
		}
	}
	
	init_generator();
	if(FLAGMODE == MODE_BSGS )	{
		printf("[+] Mode BSGS %s\n",bsgs_modes[FLAGBSGSMODE]);
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
	if(FLAGRANGE) {
		n_range_start.SetBase16(range_start);
		if(n_range_start.IsZero())	{
			n_range_start.AddOne();
		}
		n_range_end.SetBase16(range_end);
		if(n_range_start.IsEqual(&n_range_end) == false ) {
			if(  n_range_start.IsLower(&secp->order) &&  n_range_end.IsLowerOrEqual(&secp->order) )	{
				if( n_range_start.IsGreater(&n_range_end)) {
					fprintf(stderr,"[W] Opps, start range can't be great than end range. Swapping them\n");
					n_range_aux.Set(&n_range_start);
					n_range_start.Set(&n_range_end);
					n_range_end.Set(&n_range_aux);
				}
				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
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
		BSGS_N.SetInt32(DEBUGCOUNT);
		if(FLAGRANGE == 0 && FLAGBITRANGE == 0)	{
			n_range_start.SetInt32(1);
			n_range_end.Set(&secp->order);
			n_range_diff.Set(&n_range_end);
			n_range_diff.Sub(&n_range_start);
		}
		else	{
			if(FLAGBITRANGE)	{
				n_range_start.SetBase16(bit_range_str_min);
				n_range_end.SetBase16(bit_range_str_max);
				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
			}
			else	{
				if(FLAGRANGE == 0)	{
					fprintf(stderr,"[W] WTF!\n");
				}
			}
		}
	}
	N = 0;
	
	if(FLAGMODE != MODE_BSGS )	{
		if(FLAG_N){
			if(str_N[0] == '0' && str_N[1] == 'x')	{
				N_SECUENTIAL_MAX =strtol(str_N,NULL,16);
			}
			else	{
				N_SECUENTIAL_MAX =strtol(str_N,NULL,10);
			}
			
			if(N_SECUENTIAL_MAX < 1024)	{
				fprintf(stderr,"[I] n value need to be equal or great than 1024, back to defaults\n");
				FLAG_N = 0;
				N_SECUENTIAL_MAX = 0xFFFFFFFF;
			}
			if(N_SECUENTIAL_MAX % 1024 != 0)	{
				fprintf(stderr,"[I] n value need to be multiplier of  1024\n");
				FLAG_N = 0;
				N_SECUENTIAL_MAX = 0xFFFFFFFF;
			}
		}

		

		
		aux =(char*) malloc(1000);
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
			case MODE_PUB2RMD:
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

		printf("[+] Allocating memory for %" PRIu64 " elements: %.2f MB\n",N,(double)(((double) sizeof(struct address_value)*N)/(double)1048576));
		i = 0;
		addressTable = (struct address_value*) malloc(sizeof(struct address_value)*N);
		if(addressTable == NULL)	{
			fprintf(stderr,"[E] Can't alloc memory for %" PRIu64 " elements\n",N);
			exit(0);
		}
		printf("[+] Bloom filter for %" PRIu64 " elements.\n",N);
		if(N <= 1000)	{
			if(bloom_init2(&bloom,1000,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init for 10000 elements.\n");
				exit(0);
			}
		}
		else	{
			if(bloom_init2(&bloom,N,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init for %" PRIu64 " elements.\n",N);
				fprintf(stderr,"[+] man enough is enough stop it\n");
				exit(0);
			}
		}
		printf("[+] Loading data to the bloomfilter total: %.2f MB\n",(double)(((double) bloom.bytes)/(double)1048576));
		i = 0;
		switch (FLAGMODE) {
			case MODE_ADDRESS:
				aux =(char*) malloc(2*MAXLENGTHADDRESS);
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
					aux = (char*)malloc(MAXLENGTHADDRESS);
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
					aux = (char*) malloc(5*MAXLENGTHADDRESS);
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
										r = hexs2bin(aux,(uint8_t*) rawvalue);
										if(r)	{
											memcpy(addressTable[i].value,rawvalue,20);
											bloom_add(&bloom,rawvalue,MAXLENGTHADDRESS);
										}
										else	{
											fprintf(stderr,"[E] error hexs2bin\n");
										}
									break;
									case 66:	/*Compress publickey*/
									r = hexs2bin(aux+2, (uint8_t*)rawvalue);
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
										r = hexs2bin(temporal, (uint8_t*) rawvalue);
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
			case MODE_PUB2RMD:
			case MODE_RMD160:
				if(FLAGRAWDATA)	{
					aux = (char*) malloc(MAXLENGTHADDRESS);
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
					aux = (char*) malloc(3*MAXLENGTHADDRESS);
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
			printf("[+] %" PRIu64 " values were loaded\n",N);
			_sort(addressTable,N);
		}
		else	{
			printf("[+] Sorting data ...");
			_sort(addressTable,N);
			printf(" done! %" PRIu64 " values were loaded and sorted\n",N);
		}
	}
	if(FLAGMODE == MODE_BSGS )	{

		aux = (char*) malloc(1024);
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
		bsgs_found = (int*) calloc(N,sizeof(int));
		OriginalPointsBSGS.reserve(N);
		OriginalPointsBSGScompressed = (bool*) malloc(N*sizeof(bool));
		pointx_str = (char*) malloc(65);
		pointy_str = (char*) malloc(65);
		if(pointy_str == NULL || pointx_str == NULL || bsgs_found == NULL)	{
			fprintf(stderr,"[E] error malloc()\n");
			exit(0);
		}
		fseek(fd,0,SEEK_SET);
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

							if(secp->ParsePublicKeyHex(aux2,OriginalPointsBSGS[i],OriginalPointsBSGScompressed[i]))	{
								i++;
							}
							else	{
								N--;
							}

						break;
						case 130:	//With the 04

							if(secp->ParsePublicKeyHex(aux2,OriginalPointsBSGS[i],OriginalPointsBSGScompressed[i]))	{
								i++;
							}
							else	{
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
		if(bsgs_point_number > 0)	{
			printf("[+] Added %u points from file\n",bsgs_point_number);
		}
		else	{
			printf("[E] The file don't have any valid publickeys\n");
			exit(0);
		}
		BSGS_N.SetInt32(0);
		BSGS_M.SetInt32(0);
		

		BSGS_M.SetInt64(bsgs_m);


		if(FLAG_N)	{	//Custom N by the -n param
						
			/* Here we need to validate if the given string is a valid hexadecimal number or a base 10 number*/
			
			/* Now the conversion*/
			if(str_N[0] == '0' && str_N[1] == 'x' )	{	/*We expedted a hexadecimal value after 0x  -> str_N +2 */
				BSGS_N.SetBase16((char*)(str_N+2));
			}
			else	{
				BSGS_N.SetBase10(str_N);
			}
			
		}
		else	{	//Default N
			BSGS_N.SetInt64((uint64_t)0x100000000000);
		}

		if(BSGS_N.HasSqrt())	{	//If the root is exact
			BSGS_M.Set(&BSGS_N);
			BSGS_M.ModSqrt();
		}
		else	{
			fprintf(stderr,"[E] -n param doesn't have exact square root\n");
			exit(0);
		}

		BSGS_AUX.Set(&BSGS_M);
		BSGS_AUX.Mod(&BSGS_GROUP_SIZE);	
		
		if(!BSGS_AUX.IsZero()){ //If M is not divisible by  BSGS_GROUP_SIZE (1024) 
			hextemp = BSGS_GROUP_SIZE.GetBase10();
			fprintf(stderr,"[E] M value is not divisible by %s\n",hextemp);
			exit(0);
		}

		bsgs_m = BSGS_M.GetInt64();




		if(FLAGRANGE || FLAGBITRANGE)	{
			if(FLAGBITRANGE)	{	// Bit Range
				n_range_start.SetBase16(bit_range_str_min);
				n_range_end.SetBase16(bit_range_str_max);

				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
				printf("[+] Bit Range %i\n",bitrange);
				printf("[+] -- from : 0x%s\n",bit_range_str_min);
				printf("[+] -- to   : 0x%s\n",bit_range_str_max);
			}
			else	{
				printf("[+] Range \n");
				printf("[+] -- from : 0x%s\n",range_start);
				printf("[+] -- to   : 0x%s\n",range_end);
			}
		}
		else	{	//Random start

			n_range_start.SetInt32(1);
			n_range_end.Set(&secp->order);
			n_range_diff.Rand(&n_range_start,&n_range_end);
			n_range_start.Set(&n_range_diff);
		}
		BSGS_CURRENT.Set(&n_range_start);


		if(n_range_diff.IsLower(&BSGS_N) )	{
			fprintf(stderr,"[E] the given range is small\n");
			exit(0);
		}

		BSGS_M.Mult((uint64_t)KFACTOR);
		BSGS_AUX.SetInt32(20);
		BSGS_R.Set(&BSGS_M);
		BSGS_R.Mod(&BSGS_AUX);
		BSGS_M2.Set(&BSGS_M);
		BSGS_M2.Div(&BSGS_AUX);

		if(!BSGS_R.IsZero())	{ /* If BSGS_M modulo 20 is not 0*/

			BSGS_M2.AddOne();
		}
		bsgs_m2 =  BSGS_M2.GetInt64();
		BSGS_AUX.Set(&BSGS_N);
		BSGS_AUX.Div(&BSGS_M);
		BSGS_R.Set(&BSGS_N);
		BSGS_R.Mod(&BSGS_M);

		if(!BSGS_R.IsZero())	{ /* if BSGS_N modulo BSGS_M is not 0*/
			BSGS_N.Set(&BSGS_M);
			BSGS_N.Mult(&BSGS_AUX);
		}


		bsgs_m = BSGS_M.GetInt64();
		bsgs_aux = BSGS_AUX.GetInt64();
		hextemp = BSGS_N.GetBase16();
		printf("[+] N = 0x%s\n",hextemp);
		free(hextemp);


		printf("[+] Bloom filter for %" PRIu64 " elements ",bsgs_m);
		fflush(stdout);
		if(bloom_init2(&bloom_bP,bsgs_m,0.000001)	== 1){
			fprintf(stderr,"\n[E] error bloom_init\n");
			exit(0);
		}
		printf(": %.2f MB\n",(float)((uint64_t)bloom_bP.bytes/(uint64_t)1048576));
		if(FLAGDEBUG) bloom_print(&bloom_bP);

		if(bsgs_m2 > 1000)	{
			if(bloom_init2(&bloom_bPx2nd,bsgs_m2,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init for %lu elements\n",bsgs_m2);
				exit(0);
			}
		}
		else	{
			if(bloom_init2(&bloom_bPx2nd,1000,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init for 1000 elements\n");
				exit(0);
			}
		}
		if(FLAGDEBUG) bloom_print(&bloom_bPx2nd);
		printf("[+] Bloom filter for %" PRIu64 " elements : %.2f MB\n",bsgs_m2,(double)((double)bloom_bPx2nd.bytes/(double)1048576));

		BSGS_MP = secp->ComputePublicKey(&BSGS_M);
		BSGS_MP2 = secp->ComputePublicKey(&BSGS_M2);
		
		BSGS_AMP2.reserve(bsgs_m2);
		GSn.reserve(CPU_GRP_SIZE/2);

		i= 0;


		/* New aMP table just to keep the same code of JLP */
		Point bsP = secp->Negation(BSGS_MP);
		Point g = bsP;
		
		GSn[0] = g;
		
		g = secp->DoubleDirect(g);
		GSn[1] = g;

		for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
			g = secp->AddDirect(g,bsP);
			GSn[i] = g;

		}
		
		_2GSn = secp->DoubleDirect(GSn[CPU_GRP_SIZE / 2 - 1]);
		
		point_temp.Set(BSGS_MP2);
		BSGS_AMP2[0] = secp->Negation(point_temp);
		point_temp = secp->DoubleDirect(BSGS_MP2);
		
		for(i = 1; i < 20; i++)	{
			BSGS_AMP2[i] = secp->Negation(point_temp);
			point_temp2 = secp->AddDirect(point_temp,BSGS_MP2);
			point_temp.Set(point_temp2);
		}
		bytes = (uint64_t)bsgs_m2 * (uint64_t) sizeof(struct bsgs_xvalue);
		printf("[+] Allocating %.2f MB for %" PRIu64  " bP Points\n",(double)(bytes/1048576),bsgs_m2);
		
		bPtable = (struct bsgs_xvalue*) malloc(bytes);
		if(bPtable == NULL)	{
			printf("[E] error malloc()\n");
			exit(0);
		}
		memset(bPtable,0,bytes);
		
		if(FLAGSAVEREADFILE)	{
			/*Reading file for 1st bloom filter */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_0_%" PRIu64 ".blm",bsgs_m);
			fd_aux1 = fopen(buffer_bloom_file,"rb");
			if(fd_aux1 != NULL)	{
				bf_ptr = (char*) bloom_bP.bf;	/*We need to save the current bf pointer*/
				printf("[+] Reading bloom filter from file %s ..",buffer_bloom_file);
				fflush(stdout);
				readed = fread(&bloom_bP,sizeof(struct bloom),1,fd_aux1);
				if(readed != 1)	{
					fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
					exit(0);
				}
				bloom_bP.bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
				readed = fread(bloom_bP.bf,bloom_bP.bytes,1,fd_aux1);
				if(readed != 1)	{
					fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
					exit(0);
				}
				memset(rawvalue,0,32);
				if(memcmp(bloom_bP.checksum,rawvalue,32) == 0 )	{	/* Old File, we need to do the checksum*/
					if(FLAGDEBUG) printf("[D] bloom_bP.checksum is zero\n");
					sha256((char*)bloom_bP.bf,bloom_bP.bytes,bloom_bP.checksum);
					memcpy(bloom_bP.checksum_backup,bloom_bP.checksum,32);
					FLAGREADEDFILE1 = 0;	/* We mark the FLAGREADEDFILE1 to 0 to write the file with the correct checkum*/
				}
				else	{	/* new file, we need to verify the checksum */
					sha256((char*)bloom_bP.bf,bloom_bP.bytes,rawvalue);
					if(memcmp(bloom_bP.checksum,rawvalue,32) == 0 )	{	/* Verification */
						FLAGREADEDFILE1 = 1;	/* OK */
					}
					else	{
						fprintf(stderr,"[E] Error checksum file mismatch!\n");
						exit(0);
					}
					
				}
				
				
				printf(" Done!\n");
				fclose(fd_aux1);
			}
			else	{
				FLAGREADEDFILE1 = 0;
			}
			
			/*Reading file for 2nd bloom filter */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_1_%" PRIu64 ".blm",bsgs_m2);
			fd_aux2 = fopen(buffer_bloom_file,"rb");
			if(fd_aux2 != NULL)	{
				bf_ptr = (char*) bloom_bPx2nd.bf;	/*We need to save the current bf pointer*/
				printf("[+] Reading bloom filter from file %s .. ",buffer_bloom_file);
				fflush(stdout);
				readed = fread(&bloom_bPx2nd,sizeof(struct bloom),1,fd_aux2);
				if(readed != 1)	{
					fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
					exit(0);
				}
				bloom_bPx2nd.bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
				readed = fread(bloom_bPx2nd.bf,bloom_bPx2nd.bytes,1,fd_aux2);
				if(readed != 1)	{
					fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
					exit(0);
				}
				memset(rawvalue,0,32);
				if(memcmp(bloom_bPx2nd.checksum,rawvalue,32) == 0 )	{	/* Old File, we need to do the checksum*/
					if(FLAGDEBUG) printf("[D] bloom_bPx2nd.checksum is zero\n");
					sha256((char*)bloom_bPx2nd.bf,bloom_bPx2nd.bytes,bloom_bPx2nd.checksum);
					memcpy(bloom_bPx2nd.checksum_backup,bloom_bPx2nd.checksum,32);
					FLAGREADEDFILE2 = 0;	/* We mark the FLAGREADEDFILE2 to 0 to write the file with the correct checkum*/
				}
				else	{	/* new file, we need to verify the checksum */
					sha256((char*)bloom_bPx2nd.bf,bloom_bPx2nd.bytes,rawvalue);
					if(memcmp(bloom_bPx2nd.checksum,rawvalue,32) == 0 )	{	/* Verification */
						FLAGREADEDFILE2 = 1;	/* OK */
					}
					else	{
						fprintf(stderr,"[E] Error checksum file mismatch!\n");
						exit(0);
					}
				}
				printf("Done!\n");
				fclose(fd_aux2);
			}
			else	{
				FLAGREADEDFILE2 = 0;
			}
			
			/*Reading file for bPtable */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_2_%" PRIu64 ".tbl",bsgs_m2);
			fd_aux3 = fopen(buffer_bloom_file,"rb");
			if(fd_aux3 != NULL)	{
				printf("[+] Reading bP Table from file %s ..",buffer_bloom_file);
				fflush(stdout);
				fread(bPtable,bytes,1,fd_aux3);
				if(readed != 1)	{
					fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
					exit(0);
				}
				fread(checksum,32,1,fd_aux3);
				sha256((char*)bPtable,bytes,checksum_backup);
				if(memcmp(checksum,checksum_backup,32) != 0)	{
					fprintf(stderr,"[E] Checksum from file %s mismatch!!\n",buffer_bloom_file);
					exit(0);
				}
				printf(" Done!\n");
				fclose(fd_aux3);
				FLAGREADEDFILE3 = 1;
			}
			else	{
				FLAGREADEDFILE3 = 0;
			}
		}
		
		if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE3)	{	/*If just one of the files were not readed, then we need to calculate the content*/
			i = 0;
			j = 0;
			BASE = 0;
			PERTHREAD = bsgs_m /NTHREADS;
			PERTHREAD_R = bsgs_m % NTHREADS;
			temp = (struct bPload *) calloc(NTHREADS,sizeof(struct bPload));
			tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));



			if(FLAGPRECALCUTED_P_FILE)	{
				printf("[+] Reading %lu bP points from file %s\n",bsgs_m,precalculated_p_filename);
				for(i = 0; i < NTHREADS; i++)	{
					temp[i].threadid = i;
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
					temp[i].counter = i;
					if(i < NTHREADS -1)	{
						temp[i].from = BASE +1;
						temp[i].to = BASE + PERTHREAD;
						BASE+=PERTHREAD;
					}
					else	{
						temp[i].from = BASE + 1;
						temp[i].to = BASE + PERTHREAD + PERTHREAD_R;
						BASE+=(PERTHREAD + PERTHREAD_R);
					}
					if(FLAGDEBUG) printf("[I] %lu to %lu\n",temp[i].from,temp[i].to);
					s = pthread_create(&tid[i],NULL,thread_bPload,(void *)&temp[i]);
				}
			}
			total_precalculated = 0;
			do {
				sleep(1);
				total_precalculated = 0;
				for(i = 0; i < NTHREADS; i++)	{
					total_precalculated+=temp[i].counter;
				}
				printf("\r[+] processing %lu/%lu bP points : %i%%\r",total_precalculated,bsgs_m,(int) (((double)total_precalculated/(double)bsgs_m)*100));
				fflush(stdout);
			} while(total_precalculated < bsgs_m);

			for(i = 0; i < NTHREADS; i++)	{
				pthread_join(tid[i], NULL);
			}
			printf("\n");
			free(temp);
			free(tid);
			
		}
		if(!FLAGREADEDFILE1)	{
			sha256((char*)bloom_bP.bf, bloom_bP.bytes, bloom_bP.checksum);
			memcpy(bloom_bP.checksum_backup,bloom_bP.checksum,32);
		}
		
		if(!FLAGREADEDFILE2)	{
			sha256((char*)bloom_bPx2nd.bf, bloom_bPx2nd.bytes, bloom_bPx2nd.checksum);
			memcpy(bloom_bPx2nd.checksum_backup,bloom_bPx2nd.checksum,32);
		}
		if(!FLAGREADEDFILE3)	{
			printf("[+] Sorting %lu elements... ",bsgs_m2);
			fflush(stdout);
			bsgs_sort(bPtable,bsgs_m2);
			printf("Done!\n");
			fflush(stdout);
			sha256((char*)bPtable, bytes, checksum);
			memcpy(checksum_backup,checksum,32);
		}
		if(FLAGSAVEREADFILE)	{
			if(!FLAGREADEDFILE1)	{
				/* Writing file for 1st bloom filter */
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_0_%" PRIu64 ".blm",bsgs_m);
				fd_aux1 = fopen(buffer_bloom_file,"wb");
				if(fd_aux1 != NULL)	{
					printf("[+] Writing bloom filter to file %s .. ",buffer_bloom_file);
					fflush(stdout);
					readed = fwrite(&bloom_bP,sizeof(struct bloom),1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
						exit(0);
					}
					readed = fwrite(bloom_bP.bf,bloom_bP.bytes,1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
						exit(0);
					}
					printf("Done!\n");
					fclose(fd_aux1);
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
				}
			}
			if(!FLAGREADEDFILE2)	{
				/* Writing file for 2nd bloom filter */
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_1_%" PRIu64 ".blm",bsgs_m2);
				fd_aux2 = fopen(buffer_bloom_file,"wb");
				if(fd_aux2 != NULL)	{
					printf("[+] Writing bloom filter to file %s .. ",buffer_bloom_file);
					fflush(stdout);
					readed = fwrite(&bloom_bPx2nd,sizeof(struct bloom),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
						exit(0);
					}
					readed = fwrite(bloom_bPx2nd.bf,bloom_bPx2nd.bytes,1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
						exit(0);
					}
					printf("Done!\n");
					fclose(fd_aux2);					
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
				}
			}
			
			
			if(!FLAGREADEDFILE3)	{
				/* Writing file for bPtable */
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_2_%" PRIu64 ".tbl",bsgs_m2);
				fd_aux3 = fopen(buffer_bloom_file,"wb");
				if(fd_aux3 != NULL)	{
					printf("[+] Writing bP Table to file %s .. ",buffer_bloom_file);
					fflush(stdout);
					readed = fwrite(bPtable,bytes,1,fd_aux3);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
						exit(0);
					}
					readed = fwrite(checksum,32,1,fd_aux3);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
						exit(0);
					}
					printf("Done!\n");
					fclose(fd_aux3);					
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
				}
			}
		}


		i = 0;

		steps = (uint64_t *) calloc(NTHREADS,sizeof(uint64_t));
		ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
		tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
		
		for(i= 0;i < NTHREADS; i++)	{
			tt = (tothread*) malloc(sizeof(struct tothread));
			tt->nt = i;
			switch(FLAGBSGSMODE)	{
				case 0:
					s = pthread_create(&tid[i],NULL,thread_process_bsgs,(void *)tt);
				break;
				case 1:
					s = pthread_create(&tid[i],NULL,thread_process_bsgs_backward,(void *)tt);
				break;
				case 2:
					s = pthread_create(&tid[i],NULL,thread_process_bsgs_both,(void *)tt);
				break;
				case 3:
					s = pthread_create(&tid[i],NULL,thread_process_bsgs_random,(void *)tt);
				break;
				case 4:
					s = pthread_create(&tid[i],NULL,thread_process_bsgs_dance,(void *)tt);
				break;
			}
			if(s != 0)	{
				fprintf(stderr,"[E] pthread_create thread_process\n");
				exit(0);
			}
		}

		
		free(aux);
	}
	if(FLAGMODE != MODE_BSGS)	{
		steps = (uint64_t *) calloc(NTHREADS,sizeof(uint64_t));
		ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
		tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));

		for(i= 0;i < NTHREADS; i++)	{
			tt = (tothread*) malloc(sizeof(struct tothread));
			tt->nt = i;
			steps[i] = 0;
			switch(FLAGMODE)	{
				case MODE_ADDRESS:
				case MODE_XPOINT:
				case MODE_RMD160:
					s = pthread_create(&tid[i],NULL,thread_process,(void *)tt);
				break;
				case MODE_PUB2RMD:
					s = pthread_create(&tid[i],NULL,thread_pub2rmd,(void *)tt);
				break;
			}
			if(s != 0)	{
				fprintf(stderr,"[E] pthread_create thread_process\n");
				exit(0);
			}
		}
	}
	i = 0;
	
	while(i < 7)	{
		int_limits[i].SetBase10((char*)str_limits[i]);
		i++;
	}
	
	continue_flag = 1;
	total.SetInt32(0);
	pretotal.SetInt32(0);
	debugcount_mpz.Set(&BSGS_N);
	seconds.SetInt32(0);
	do	{
		sleep(1);
		seconds.AddOne();
		check_flag = 1;
		for(i = 0; i <NTHREADS && check_flag; i++) {
			check_flag &= ends[i];
		}
		if(check_flag)	{
			continue_flag = 0;
		}
		if(OUTPUTSECONDS.IsGreater(&ZERO) ){
			MPZAUX.Set(&seconds);
			MPZAUX.Mod(&OUTPUTSECONDS);
			if(MPZAUX.IsZero()) {
				total.SetInt32(0);
				i = 0;
				while(i < NTHREADS) {
					pretotal.Set(&debugcount_mpz);
					pretotal.Mult(steps[i]);
					total.Add(&pretotal);
					i++;
				}
				
				pthread_mutex_lock(&bsgs_thread);
				pretotal.Set(&total);
				pretotal.Div(&seconds);
				str_seconds = seconds.GetBase10();
				str_pretotal = pretotal.GetBase10();
				str_total = total.GetBase10();
				
				
				if(pretotal.IsLower(&int_limits[0]))	{
					if(FLAGMATRIX)	{
						sprintf(buffer,"[+] Total %s keys in %s seconds: %s keys/s\n",str_total,str_seconds,str_pretotal);
					}
					else	{
						sprintf(buffer,"\r[+] Total %s keys in %s seconds: %s keys/s\r",str_total,str_seconds,str_pretotal);
					}
				}
				else	{
					i = 0;
					salir = 0;
					while( i < 6 && !salir)	{
						if(pretotal.IsLower(&int_limits[i+1]))	{
							salir = 1;
						}
						else	{
							i++;
						}
					}

					div_pretotal.Set(&pretotal);
					div_pretotal.Div(&int_limits[salir ? i : i-1]);
					str_divpretotal = div_pretotal.GetBase10();
					if(FLAGMATRIX)	{
						sprintf(buffer,"[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\n",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
					}
					else	{
						if(THREADOUTPUT == 1)	{
							sprintf(buffer,"\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\r",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
						}
						else	{
							sprintf(buffer,"\r[+] Total %s keys in %s seconds: ~%s %s (%s keys/s)\r",str_total,str_seconds,str_divpretotal,str_limits_prefixs[salir ? i : i-1],str_pretotal);
						}
					}
					free(str_divpretotal);

				}
				
				

				printf("%s",buffer);
				fflush(stdout);
				THREADOUTPUT = 0;
				pthread_mutex_unlock(&bsgs_thread);
				free(str_seconds);
				free(str_pretotal);
				free(str_total);
			}
		}
	}while(continue_flag);
}

char *pubkeytopubaddress(char *pkey,int length)	{
	char *pubaddress = (char*) calloc(MAXLENGTHADDRESS+10,1);
	char *digest = (char*) calloc(60,1);
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
	char *hash160 = (char*) malloc(20);
	char *digest = (char*) malloc(32);
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
	Point pts[CPU_GRP_SIZE];
	Int dx[CPU_GRP_SIZE / 2 + 1];
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Point pp;
	Point pn;
	int hLength = (CPU_GRP_SIZE / 2 - 1);
	uint64_t i,j,count;
	Point R,temporal;
	int r,thread_number,found,continue_flag = 1;
	char *public_key_compressed,*public_key_uncompressed,hexstrpoint[65],rawvalue[32];
	char *publickeyhashrmd160_compress,*publickeyhashrmd160_uncompress;
	char *hextemp,*public_key_compressed_hex,*public_key_uncompressed_hex;
	char *eth_address;
	char *public_address_compressed,*public_address_uncompressed;
	unsigned long longtemp;
	FILE *keys,*vanityKeys;
	Int key_mpz,mpz_bit_range_min,mpz_bit_range_max,mpz_bit_range_diff;
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	found = 0;
	grp->Set(dx);
	do {
		
		if(FLAGRANDOM){
			key_mpz.Rand(&n_range_start,&n_range_end);
		}
		else	{
			if(n_range_start.IsLower(&n_range_end))	{
				pthread_mutex_lock(&write_random);
				key_mpz.Set(&n_range_start);
				n_range_start.Add(N_SECUENTIAL_MAX);
				pthread_mutex_unlock(&write_random);
			}
			else	{
				continue_flag = 0;
			}
		}
		if(continue_flag)	{
			count = 0;
			do {
				if(FLAGMATRIX)	{
						hextemp = key_mpz.GetBase16();
						printf("Base key: %s\n",hextemp);
						fflush(stdout);
						free(hextemp);
				}
				else	{
					if(FLAGQUIET == 0){
						hextemp = key_mpz.GetBase16();
						printf("\rBase key: %s     \r",hextemp);
						fflush(stdout);
						free(hextemp);
						THREADOUTPUT = 1;
					}
				}
				key_mpz.Add((uint64_t)CPU_GRP_SIZE / 2);
	 			startP = secp->ComputePublicKey(&key_mpz);
				key_mpz.Sub((uint64_t)CPU_GRP_SIZE / 2);

				for(i = 0; i < hLength; i++) {
					dx[i].ModSub(&Gn[i].x,&startP.x);
				}
			
		    dx[i].ModSub(&Gn[i].x,&startP.x);  // For the first point
		    dx[i + 1].ModSub(&_2Gn.x,&startP.x); // For the next center point
			grp->ModInv();

			pts[CPU_GRP_SIZE / 2] = startP;

			for(i = 0; i<hLength; i++) {
				pp = startP;
				pn = startP;

				// P = startP + i*G
				dy.ModSub(&Gn[i].y,&pp.y);

				_s.ModMulK1(&dy,&dx[i]);        // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
				_p.ModSquareK1(&_s);            // _p = pow2(s)

				pp.x.ModNeg();
				pp.x.ModAdd(&_p);
				pp.x.ModSub(&Gn[i].x);           // rx = pow2(s) - p1.x - p2.x;

				if(FLAGMODE != MODE_XPOINT  )	{
					pp.y.ModSub(&Gn[i].x,&pp.x);
					pp.y.ModMulK1(&_s);
					pp.y.ModSub(&Gn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);
				}

				// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
				dyn.Set(&Gn[i].y);
				dyn.ModNeg();
				dyn.ModSub(&pn.y);

				_s.ModMulK1(&dyn,&dx[i]);      // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
				_p.ModSquareK1(&_s);            // _p = pow2(s)
				pn.x.ModNeg();
				pn.x.ModAdd(&_p);
				pn.x.ModSub(&Gn[i].x);          // rx = pow2(s) - p1.x - p2.x;

				if(FLAGMODE != MODE_XPOINT  )	{
					pn.y.ModSub(&Gn[i].x,&pn.x);
					pn.y.ModMulK1(&_s);
					pn.y.ModAdd(&Gn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);
				}

				pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
				pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
			}

			// First point (startP - (GRP_SZIE/2)*G)
		    pn = startP;
		    dyn.Set(&Gn[i].y);
		    dyn.ModNeg();
		    dyn.ModSub(&pn.y);

		    _s.ModMulK1(&dyn,&dx[i]);
		    _p.ModSquareK1(&_s);

		    pn.x.ModNeg();
		    pn.x.ModAdd(&_p);
		    pn.x.ModSub(&Gn[i].x);
			
			if(FLAGMODE != MODE_XPOINT  )	{
			    pn.y.ModSub(&Gn[i].x,&pn.x);
			    pn.y.ModMulK1(&_s);
			    pn.y.ModAdd(&Gn[i].y);
			}

		    pts[0] = pn;


				for(j = 0; j < CPU_GRP_SIZE;j++){
					switch(FLAGMODE)	{
						case MODE_ADDRESS:
						case MODE_RMD160:
							switch(FLAGSEARCH)	{
								case SEARCH_UNCOMPRESS:
									public_key_uncompressed = secp->GetPublicKeyRaw(false,pts[j]);
								break;
								case SEARCH_COMPRESS:
									public_key_compressed = secp->GetPublicKeyRaw(true,pts[j]);
								break;
								case SEARCH_BOTH:
									public_key_uncompressed = secp->GetPublicKeyRaw(false,pts[j]);
									public_key_compressed = secp->GetPublicKeyRaw(true,pts[j]);
								break;
							}
						break;
					}
					switch(FLAGMODE)	{
						case MODE_ADDRESS:
							if( (FLAGCRYPTO | CRYPTO_BTC) != 0) {
								
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
											hextemp = key_mpz.GetBase16();
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
											hextemp = key_mpz.GetBase16();
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
											hextemp = key_mpz.GetBase16();
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
											hextemp = key_mpz.GetBase16();
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
							}
							if( ( FLAGCRYPTO | CRYPTO_ETH ) != 0) {
							
								generate_binaddress_eth(&pts[j],(unsigned char*)rawvalue);
								
								r = bloom_check(&bloom,rawvalue+12,MAXLENGTHADDRESS);
								if(r) {
									r = searchbinary(addressTable,rawvalue+12,N);
									if(r) {
										found++;
										hextemp = key_mpz.GetBase16();
										hexstrpoint[0] = '0';
										hexstrpoint[1] = 'x';
										tohex_dst(rawvalue+12,20,hexstrpoint+2);
										
										pthread_mutex_lock(&write_keys);
										keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
										if(keys != NULL)	{
											fprintf(keys,"PrivKey: %s\naddress: %s\n",hextemp,hexstrpoint);
											fclose(keys);
										}
										printf("\n Hit!!!! PrivKey: %s\naddress: %s\n",hextemp,hexstrpoint);
										pthread_mutex_unlock(&write_keys);
										free(hextemp);
									}
								}

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
										hextemp = key_mpz.GetBase16();
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
										hextemp = key_mpz.GetBase16();
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
							pts[j].x.Get32Bytes((unsigned char *)rawvalue);
							r = bloom_check(&bloom,rawvalue,MAXLENGTHADDRESS);
							if(r) {
								r = searchbinary(addressTable,rawvalue,N);
								if(r) {
									found++;
									hextemp = key_mpz.GetBase16();
									R = secp->ComputePublicKey(&key_mpz);
									public_key_compressed = secp->GetPublicKeyHex(true,R);
									printf("\nHIT!! PrivKey: %s\npubkey: %s\n",hextemp,public_key_compressed);
									pthread_mutex_lock(&write_keys);
									keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
									if(keys != NULL)	{
										fprintf(keys,"PrivKey: %s\npubkey: %s\n",hextemp,public_key_compressed);
										fclose(keys);
									}
									pthread_mutex_unlock(&write_keys);
									free(public_key_compressed);
									free(hextemp);
								}
							}
						break;
					}
					if(FLAGMODE == MODE_ADDRESS || FLAGMODE == MODE_RMD160)	{
						switch(FLAGSEARCH)	{
							case SEARCH_UNCOMPRESS:
								free(public_key_uncompressed);
							break;
							case SEARCH_COMPRESS:
								free(public_key_compressed);
							break;
							case SEARCH_BOTH:
								free(public_key_compressed);
								free(public_key_uncompressed);
							break;
						}
					}
					count++;
					if(count % DEBUGCOUNT == 0 )	{
						steps[thread_number]++;
					}
					key_mpz.AddOne();
				}



				// Next start point (startP + GRP_SIZE*G)
		    pp = startP;
		    dy.ModSub(&_2Gn.y,&pp.y);

		    _s.ModMulK1(&dy,&dx[i + 1]);
		    _p.ModSquareK1(&_s);

		    pp.x.ModNeg();
		    pp.x.ModAdd(&_p);
		    pp.x.ModSub(&_2Gn.x);

		    pp.y.ModSub(&_2Gn.x,&pp.x);
		    pp.y.ModMulK1(&_s);
		    pp.y.ModSub(&_2Gn.y);
		    startP = pp;
			}while(count <= N_SECUENTIAL_MAX && continue_flag);
		}
	} while(continue_flag);
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
	FILE *filekey;
	struct tothread *tt;
	char xpoint_raw[32],*aux_c,*hextemp;
	Int base_key,keyfound;
	Point base_point,point_aux,point_found;
	uint32_t i,j,k,r,salir,thread_number,flip_detector;
	
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	
	int hLength = (CPU_GRP_SIZE / 2 - 1);
	
	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];

	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Int km,intaux;
	Point pp;
	Point pn;
	grp->Set(dx);

	
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);

	pthread_mutex_lock(&bsgs_thread);
	/* we need to set our base_key to the current BSGS_CURRENT value*/
	base_key.Set(&BSGS_CURRENT);
	BSGS_CURRENT.Add(&BSGS_N);
	
	/*Then add BSGS_N to BSGS_CURRENT*/
	/*
		We do this in an atomic pthread_mutex operation to not affect others threads
		so BSGS_CURRENT is never the same between threads
	*/
	pthread_mutex_unlock(&bsgs_thread);
	
	intaux.Set(&BSGS_M);
	intaux.Mult(CPU_GRP_SIZE/2);
	
	flip_detector = 1000000;
	
	/*
		while base_key is less than n_range_end then:
	*/
	while(base_key.IsLower(&n_range_end) )	{
		if(thread_number == 0 && flip_detector == 0)	{
			memorycheck();
			flip_detector = 1000000;
		}
		
		if(FLAGMATRIX)	{
			aux_c = base_key.GetBase16();
			printf("[+] Thread 0x%s \n",aux_c);
			fflush(stdout);
			free(aux_c);
		}
		else	{
			if(FLAGQUIET == 0){
				aux_c = base_key.GetBase16();
				printf("\r[+] Thread 0x%s   \r",aux_c);
				fflush(stdout);
				free(aux_c);
				THREADOUTPUT = 1;
			}
		}
		
		base_point = secp->ComputePublicKey(&base_key);

		km.Set(&base_key);
		km.Neg();
		
		km.Add(&secp->order);
		km.Sub(&intaux);
		point_aux = secp->ComputePublicKey(&km);
		
		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
				if(base_point.equals(OriginalPointsBSGS[k]))	{
					hextemp = base_key.GetBase16();
					printf("[+] Thread Key found privkey %s  \n",hextemp);
					aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],base_point);
					printf("[+] Publickey %s\n",aux_c);
					
					pthread_mutex_lock(&write_keys);
					filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
					if(filekey != NULL)	{
						fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
						fclose(filekey);
					}
					free(hextemp);
					free(aux_c);
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
					startP  = secp->AddDirect(OriginalPointsBSGS[k],point_aux);
					int j = 0;
					while( j < bsgs_aux/1024 && bsgs_found[k]== 0 )	{
					
						int i;
						
						for(i = 0; i < hLength; i++) {
							dx[i].ModSub(&GSn[i].x,&startP.x);
						}
						dx[i].ModSub(&GSn[i].x,&startP.x);  // For the first point
						dx[i+1].ModSub(&_2GSn.x,&startP.x); // For the next center point

						// Grouped ModInv
						grp->ModInv();
						
						/*
						We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
						We compute key in the positive and negative way from the center of the group
						*/

						// center point
						pts[CPU_GRP_SIZE / 2] = startP;
						
						for(i = 0; i<hLength; i++) {

							pp = startP;
							pn = startP;

							// P = startP + i*G
							dy.ModSub(&GSn[i].y,&pp.y);

							_s.ModMulK1(&dy,&dx[i]);        // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
							_p.ModSquareK1(&_s);            // _p = pow2(s)

							pp.x.ModNeg();
							pp.x.ModAdd(&_p);
							pp.x.ModSub(&GSn[i].x);           // rx = pow2(s) - p1.x - p2.x;
							
#if 0
	  pp.y.ModSub(&GSn[i].x,&pp.x);
	  pp.y.ModMulK1(&_s);
	  pp.y.ModSub(&GSn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);  
#endif

							// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
							dyn.Set(&GSn[i].y);
							dyn.ModNeg();
							dyn.ModSub(&pn.y);

							_s.ModMulK1(&dyn,&dx[i]);       // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
							_p.ModSquareK1(&_s);            // _p = pow2(s)

							pn.x.ModNeg();
							pn.x.ModAdd(&_p);
							pn.x.ModSub(&GSn[i].x);          // rx = pow2(s) - p1.x - p2.x;

#if 0
	  pn.y.ModSub(&GSn[i].x,&pn.x);
	  pn.y.ModMulK1(&_s);
	  pn.y.ModAdd(&GSn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);  
#endif


							pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
							pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;

						}

						// First point (startP - (GRP_SZIE/2)*G)
						pn = startP;
						dyn.Set(&GSn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);

						_s.ModMulK1(&dyn,&dx[i]);
						_p.ModSquareK1(&_s);

						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&GSn[i].x);

#if 0
	pn.y.ModSub(&GSn[i].x,&pn.x);
	pn.y.ModMulK1(&_s);
	pn.y.ModAdd(&GSn[i].y);
#endif

						pts[0] = pn;
						
						for(int i = 0; i<CPU_GRP_SIZE && bsgs_found[k]== 0; i++) {
							pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
							r = bloom_check(&bloom_bP,xpoint_raw,32);
							if(r) {
								r = bsgs_secondcheck(&base_key,((j*1024) + i),k,&keyfound);
								if(r)	{
									hextemp = keyfound.GetBase16();
									printf("[+] Thread Key found privkey %s   \n",hextemp);
									point_found = secp->ComputePublicKey(&keyfound);
									aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],point_found);
									printf("[+] Publickey %s\n",aux_c);
									pthread_mutex_lock(&write_keys);
									filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
									if(filekey != NULL)	{
										fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
										fclose(filekey);
									}
									free(hextemp);
									free(aux_c);
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
								} //End if second check
							}//End if first check
							
						}// For for pts variable
						
						// Next start point (startP += (bsSize*GRP_SIZE).G)
						
						pp = startP;
						dy.ModSub(&_2GSn.y,&pp.y);

						_s.ModMulK1(&dy,&dx[i + 1]);
						_p.ModSquareK1(&_s);

						pp.x.ModNeg();
						pp.x.ModAdd(&_p);
						pp.x.ModSub(&_2GSn.x);

						pp.y.ModSub(&_2GSn.x,&pp.x);
						pp.y.ModMulK1(&_s);
						pp.y.ModSub(&_2GSn.y);
						startP = pp;
						
						j++;
					}//while all the aMP points
				}// end else
			}// End if 
		}
			
		steps[thread_number]++;
		pthread_mutex_lock(&bsgs_thread);
		base_key.Set(&BSGS_CURRENT);
		BSGS_CURRENT.Add(&BSGS_N);
		pthread_mutex_unlock(&bsgs_thread);
		flip_detector--;
	}
	ends[thread_number] = 1;
	return NULL;
}

void *thread_process_bsgs_random(void *vargp)	{
	FILE *filekey;
	struct tothread *tt;
	char xpoint_raw[32],*aux_c,*hextemp;
	Int base_key,keyfound,n_range_random;
	Point base_point,point_aux,point_found;
	uint32_t i,j,k,r,salir,thread_number,flip_detector;
	
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	
	int hLength = (CPU_GRP_SIZE / 2 - 1);
	
	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];

	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Int km,intaux;
	Point pp;
	Point pn;
	grp->Set(dx);


	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	/*          | Start Range	| End Range     |
		None	| 1             | EC.N          |
		-b	bit | Min bit value | Max bit value |
		-r	A:B | A             | B             |
	*/
	pthread_mutex_lock(&bsgs_thread);
	base_key.Rand(&n_range_start,&n_range_end);
	pthread_mutex_unlock(&bsgs_thread);

	intaux.Set(&BSGS_M);
	intaux.Mult(CPU_GRP_SIZE/2);
	flip_detector = 1000000;
	/*
		while base_key is less than n_range_end then:
	*/
	while(base_key.IsLower(&n_range_end))	{
		if(thread_number == 0 && flip_detector == 0)	{
			memorycheck();
			flip_detector = 1000000;
		}
		if(FLAGMATRIX)	{
				aux_c = base_key.GetBase16();
				printf("[+] Thread 0x%s  \n",aux_c);
				fflush(stdout);
				free(aux_c);
		}
		else{
			if(FLAGQUIET == 0){
				aux_c = base_key.GetBase16();
				printf("\r[+] Thread 0x%s  \r",aux_c);
				fflush(stdout);
				free(aux_c);
				THREADOUTPUT = 1;
			}
		}
		base_point = secp->ComputePublicKey(&base_key);

		km.Set(&base_key);
		km.Neg();
		
		
		km.Add(&secp->order);
		km.Sub(&intaux);
		point_aux = secp->ComputePublicKey(&km);


		/* We need to test individually every point in BSGS_Q */
		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
				if(base_point.equals(OriginalPointsBSGS[k]))	{
					hextemp = base_key.GetBase16();
					printf("[+] Thread Key found privkey %s     \n",hextemp);
					aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],base_point);
					printf("[+] Publickey %s\n",aux_c);
					
					pthread_mutex_lock(&write_keys);
					filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
					if(filekey != NULL)	{
						fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
						fclose(filekey);
					}
					free(hextemp);
					free(aux_c);
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
				
					startP  = secp->AddDirect(OriginalPointsBSGS[k],point_aux);
					int j = 0;
					while( j < bsgs_aux/1024 && bsgs_found[k]== 0 )	{
					
						int i;
						for(i = 0; i < hLength; i++) {
							dx[i].ModSub(&GSn[i].x,&startP.x);
						}
						dx[i].ModSub(&GSn[i].x,&startP.x);  // For the first point
						dx[i+1].ModSub(&_2GSn.x,&startP.x); // For the next center point

						// Grouped ModInv
						grp->ModInv();
						
						/*
						We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
						We compute key in the positive and negative way from the center of the group
						*/

						// center point
						pts[CPU_GRP_SIZE / 2] = startP;
						
						for(i = 0; i<hLength; i++) {

							pp = startP;
							pn = startP;

							// P = startP + i*G
							dy.ModSub(&GSn[i].y,&pp.y);

							_s.ModMulK1(&dy,&dx[i]);        // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
							_p.ModSquareK1(&_s);            // _p = pow2(s)

							pp.x.ModNeg();
							pp.x.ModAdd(&_p);
							pp.x.ModSub(&GSn[i].x);           // rx = pow2(s) - p1.x - p2.x;
							
#if 0
	  pp.y.ModSub(&GSn[i].x,&pp.x);
	  pp.y.ModMulK1(&_s);
	  pp.y.ModSub(&GSn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);  
#endif

							// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
							dyn.Set(&GSn[i].y);
							dyn.ModNeg();
							dyn.ModSub(&pn.y);

							_s.ModMulK1(&dyn,&dx[i]);       // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
							_p.ModSquareK1(&_s);            // _p = pow2(s)

							pn.x.ModNeg();
							pn.x.ModAdd(&_p);
							pn.x.ModSub(&GSn[i].x);          // rx = pow2(s) - p1.x - p2.x;

#if 0
	  pn.y.ModSub(&GSn[i].x,&pn.x);
	  pn.y.ModMulK1(&_s);
	  pn.y.ModAdd(&GSn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);  
#endif


							pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
							pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;

						}

						// First point (startP - (GRP_SZIE/2)*G)
						pn = startP;
						dyn.Set(&GSn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);

						_s.ModMulK1(&dyn,&dx[i]);
						_p.ModSquareK1(&_s);

						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&GSn[i].x);

#if 0
	pn.y.ModSub(&GSn[i].x,&pn.x);
	pn.y.ModMulK1(&_s);
	pn.y.ModAdd(&GSn[i].y);
#endif

						pts[0] = pn;
						
						for(int i = 0; i<CPU_GRP_SIZE && bsgs_found[k]== 0; i++) {
							pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
							r = bloom_check(&bloom_bP,xpoint_raw,32);
							if(r) {
								r = bsgs_secondcheck(&base_key,((j*1024) + i),k,&keyfound);
								if(r)	{
									hextemp = keyfound.GetBase16();
									printf("[+] Thread Key found privkey %s    \n",hextemp);
									point_found = secp->ComputePublicKey(&keyfound);
									aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],point_found);
									printf("[+] Publickey %s\n",aux_c);
									pthread_mutex_lock(&write_keys);
									filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
									if(filekey != NULL)	{
										fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
										fclose(filekey);
									}
									free(hextemp);
									free(aux_c);
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
								} //End if second check
							}//End if first check
							
						}// For for pts variable
						
						// Next start point (startP += (bsSize*GRP_SIZE).G)
						
						pp = startP;
						dy.ModSub(&_2GSn.y,&pp.y);

						_s.ModMulK1(&dy,&dx[i + 1]);
						_p.ModSquareK1(&_s);

						pp.x.ModNeg();
						pp.x.ModAdd(&_p);
						pp.x.ModSub(&_2GSn.x);

						pp.y.ModSub(&_2GSn.x,&pp.x);
						pp.y.ModMulK1(&_s);
						pp.y.ModSub(&_2GSn.y);
						startP = pp;
						
						j++;
						
					}	//End While

					
					
				} //End else

				
			}	//End if
		} // End for with k bsgs_point_number

		steps[thread_number]++;
		pthread_mutex_lock(&bsgs_thread);
		base_key.Rand(&n_range_start,&n_range_end);
		pthread_mutex_unlock(&bsgs_thread);
		flip_detector--;
	}
	ends[thread_number] = 1;
	return NULL;
}

/*
	The bsgs_secondcheck function is made to perform a second BSGS search in a Range of less size.
	This funtion is made with the especific purpouse to USE a smaller bPtable in RAM.
	This new and small bPtable is around ~ squareroot( K *squareroot(N))
*/
int bsgs_secondcheck(Int *start_range,uint32_t a,uint32_t k_index,Int *privatekey)	{
	uint64_t j = 0;
	int i = 0,found = 0,r = 0;
	Int base_key;
	Point base_point,point_aux;
	Point BSGS_Q, BSGS_S,BSGS_Q_AMP;
	char pubkey[131],xpoint_str[65],xpoint_raw[32],*hexvalue;

	base_key.Set(&BSGS_M);
	base_key.Mult((uint64_t) a);
	base_key.Add(start_range);

	base_point = secp->ComputePublicKey(&base_key);
	point_aux = secp->Negation(base_point);

	BSGS_S = secp->AddDirect(OriginalPointsBSGS[k_index],point_aux);

	BSGS_Q.Set(BSGS_S);

	do {
		BSGS_S.x.Get32Bytes((unsigned char *)xpoint_raw);
		r = bloom_check(&bloom_bPx2nd,xpoint_raw,32);
		if(r)	{
			r = bsgs_searchbinary(bPtable,xpoint_raw,bsgs_m2,&j);
			if(r)	{
				privatekey->Set(&BSGS_M2);
				privatekey->Mult((uint64_t)i);
				privatekey->Add((uint64_t)(j+1));
				privatekey->Add(&base_key);
				point_aux = secp->ComputePublicKey(privatekey);
				if(point_aux.x.IsEqual(&OriginalPointsBSGS[k_index].x))	{
					found = 1;
				}
				else	{
					privatekey->Set(&BSGS_M2);
					privatekey->Mult((uint64_t)i);
					privatekey->Sub((uint64_t)(j+1));
					privatekey->Add(&base_key);
					point_aux = secp->ComputePublicKey(privatekey);
					if(point_aux.x.IsEqual(&OriginalPointsBSGS[k_index].x))	{
						found = 1;
					}
				}
			}
		}
		BSGS_Q_AMP = secp->AddDirect(BSGS_Q,BSGS_AMP2[i]);
		BSGS_S.Set(BSGS_Q_AMP);
		i++;
	}while(i < 20 && !found);
	return found;
}

void *thread_bPloadFile(void *vargp)	{
	FILE *fd;
	char rawvalue[32],*hextemp;
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
	if(fseek(fd,(uint64_t)(i*32),SEEK_SET) != 0)	{
		fprintf(stderr,"Can't seek the file at index %" PRIu64 ", offset %" PRIu64 "\n",i,(uint64_t)(i*32));
		exit(0);
	}
	do {
		if(fread(rawvalue,1,32,fd) == 32)	{

			if(i < bsgs_m2)	{
				if(!FLAGREADEDFILE3)	{
					memcpy(bPtable[j].value,rawvalue+16,BSGS_XVALUE_RAM);
					bPtable[j].index = j;
				}
				if(!FLAGREADEDFILE2)
					bloom_add(&bloom_bPx2nd, rawvalue, BSGS_BUFFERXPOINTLENGTH);
				j++;
			}
			if(!FLAGREADEDFILE1)
				bloom_add(&bloom_bP, rawvalue ,BSGS_BUFFERXPOINTLENGTH);
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

void *thread_pub2rmd(void *vargp)	{
	FILE *fd;
	Int key_mpz;
	struct tothread *tt;
	uint64_t i,limit,j;
	char digest160[20];
	char digest256[32];
	char *temphex;
	int thread_number,r;
	int pub2rmd_continue = 1;
	struct publickey pub;
	limit = 0xFFFFFFFF;
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	do {
		if(FLAGRANDOM){
			key_mpz.Rand(&n_range_start,&n_range_diff);
		}
		else	{
			if(n_range_start.IsLower(&n_range_end))	{
				pthread_mutex_lock(&write_random);
				key_mpz.Set(&n_range_start);
				n_range_start.Add(N_SECUENTIAL_MAX);
				pthread_mutex_unlock(&write_random);
			}
			else	{
				pub2rmd_continue = 0;
			}
		}
		if(pub2rmd_continue)	{
			key_mpz.Get32Bytes(pub.X.data8);
			pub.parity = 0x02;
			pub.X.data32[7] = 0;
			if(FLAGMATRIX)	{
				temphex = tohex((char*)&pub,33);
				printf("[+] Thread 0x%s  \n",temphex);
				free(temphex);
				fflush(stdout);
			}
			else	{
				if(FLAGQUIET == 0)	{
					temphex = tohex((char*)&pub,33);
					printf("\r[+] Thread %s  \r",temphex);
					free(temphex);
					fflush(stdout);
					THREADOUTPUT = 1;
				}
			}
			for(i = 0 ; i < limit ; i++) {
				pub.parity = 0x02;
				sha256((char*)&pub, 33, digest256);
				RMD160Data((const unsigned char*)digest256,32, digest160);
				r = bloom_check(&bloom,digest160,MAXLENGTHADDRESS);
				if(r)  {
						r = searchbinary(addressTable,digest160,N);
						if(r)	{
							temphex = tohex((char*)&pub,33);
							printf("\nHit: Publickey found %s\n",temphex);
							fd = fopen("KEYFOUNDKEYFOUND.txt","a+");
							if(fd != NULL)	{
								pthread_mutex_lock(&write_keys);
								fprintf(fd,"Publickey found %s\n",temphex);
								fclose(fd);
								pthread_mutex_unlock(&write_keys);
							}
							else	{
								fprintf(stderr,"\nPublickey found %s\nbut the file can't be open\n",temphex);
								exit(0);
							}
							free(temphex);
						}
				}
				pub.parity = 0x03;
				sha256((char*)&pub, 33, digest256);
				RMD160Data((const unsigned char*)digest256,32, digest160);
				r = bloom_check(&bloom,digest160,MAXLENGTHADDRESS);
				if(r)  {
					r = searchbinary(addressTable,digest160,N);
					if(r)  {
						temphex = tohex((char*)&pub,33);
						printf("\nHit: Publickey found %s\n",temphex);
						fd = fopen("KEYFOUNDKEYFOUND.txt","a+");
						if(fd != NULL)	{
							pthread_mutex_lock(&write_keys);
							fprintf(fd,"Publickey found %s\n",temphex);
							fclose(fd);
							pthread_mutex_unlock(&write_keys);
						}
						else	{
							fprintf(stderr,"\nPublickey found %s\nbut the file can't be open\n",temphex);
							exit(0);
						}
						free(temphex);
					}
				}
				pub.X.data32[7]++;
				if(pub.X.data32[7] % DEBUGCOUNT == 0)  {
					steps[thread_number]++;
				}
			}	/* End for */
		}	/* End if */
	}while(pub2rmd_continue);
	ends[thread_number] = 1;
	return NULL;
}

void init_generator()	{
	Point g = secp->G;
	Gn.reserve(CPU_GRP_SIZE / 2);
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g,secp->G);
		Gn[i] = g;
	}
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
}

void *thread_bPload(void *vargp)	{
	char *hextemp,rawvalue[32];
	struct bPload *tt;
	uint64_t j_counter,i_counter;
	uint64_t i,j,nbStep;
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];
	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Point pp;
	Point pn;
	int hLength = (CPU_GRP_SIZE / 2 - 1);
	tt = (struct bPload *)vargp;
	Int km(tt->from);
	if(FLAGDEBUG) printf("[D] thread %i from %" PRIu64 " to %" PRIu64 "\n",tt->threadid,tt->from,tt->to);
	i_counter = tt->from -1;
	j_counter = tt->from -1;

	nbStep = (tt->to - (tt->from-1)) / CPU_GRP_SIZE;
	if( ((tt->to - (tt->from-1)) % CPU_GRP_SIZE )  != 0)	{
		nbStep++;
	}
	km.Add((uint64_t)(CPU_GRP_SIZE / 2));
	startP = secp->ComputePublicKey(&km);
	grp->Set(dx);

	for(uint64_t s=0;s<nbStep;s++) {
		for(i = 0; i < hLength; i++) {
			dx[i].ModSub(&Gn[i].x,&startP.x);
		}
		dx[i].ModSub(&Gn[i].x,&startP.x); // For the first point
		dx[i + 1].ModSub(&_2Gn.x,&startP.x);// For the next center point
		// Grouped ModInv
		grp->ModInv();

		// We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
		// We compute key in the positive and negative way from the center of the group
		// center point
		
		pts[CPU_GRP_SIZE / 2] = startP;	//Center point

		for(i = 0; i<hLength; i++) {
			pp = startP;
			pn = startP;

			// P = startP + i*G
			dy.ModSub(&Gn[i].y,&pp.y);

			_s.ModMulK1(&dy,&dx[i]);        // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
			_p.ModSquareK1(&_s);            // _p = pow2(s)

			pp.x.ModNeg();
			pp.x.ModAdd(&_p);
			pp.x.ModSub(&Gn[i].x);           // rx = pow2(s) - p1.x - p2.x;

#if 0
			pp.y.ModSub(&Gn[i].x,&pp.x);
			pp.y.ModMulK1(&_s);
			pp.y.ModSub(&Gn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);
#endif

			// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
			dyn.Set(&Gn[i].y);
			dyn.ModNeg();
			dyn.ModSub(&pn.y);

			_s.ModMulK1(&dyn,&dx[i]);      // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
			_p.ModSquareK1(&_s);            // _p = pow2(s)

			pn.x.ModNeg();
			pn.x.ModAdd(&_p);
			pn.x.ModSub(&Gn[i].x);          // rx = pow2(s) - p1.x - p2.x;

#if 0
			pn.y.ModSub(&Gn[i].x,&pn.x);
			pn.y.ModMulK1(&_s);
			pn.y.ModAdd(&Gn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);
#endif

			pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
			pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;
		}

		// First point (startP - (GRP_SZIE/2)*G)
		pn = startP;
		dyn.Set(&Gn[i].y);
		dyn.ModNeg();
		dyn.ModSub(&pn.y);

		_s.ModMulK1(&dyn,&dx[i]);
		_p.ModSquareK1(&_s);

		pn.x.ModNeg();
		pn.x.ModAdd(&_p);
		pn.x.ModSub(&Gn[i].x);

#if 0
		pn.y.ModSub(&Gn[i].x,&pn.x);
		pn.y.ModMulK1(&_s);
		pn.y.ModAdd(&Gn[i].y);
#endif

		pts[0] = pn;
		for(j=0;j<CPU_GRP_SIZE;j++)	{
			pts[j].x.Get32Bytes((unsigned char*)rawvalue);

			if(i_counter < bsgs_m2)	{
				if(!FLAGREADEDFILE3)	{
					memcpy(bPtable[j_counter].value,rawvalue+16,BSGS_XVALUE_RAM);
					bPtable[j_counter].index = j_counter;
				}
				if(!FLAGREADEDFILE2)
					bloom_add(&bloom_bPx2nd, rawvalue, BSGS_BUFFERXPOINTLENGTH);
				j_counter++;
			}
			if(i_counter < tt->to)	{
				if(!FLAGREADEDFILE1)
					bloom_add(&bloom_bP, rawvalue ,BSGS_BUFFERXPOINTLENGTH);
				tt->counter++;
				i_counter++;
			}
		}
		// Next start point (startP + GRP_SIZE*G)
		pp = startP;
		dy.ModSub(&_2Gn.y,&pp.y);

		_s.ModMulK1(&dy,&dx[i + 1]);
		_p.ModSquareK1(&_s);

		pp.x.ModNeg();
		pp.x.ModAdd(&_p);
		pp.x.ModSub(&_2Gn.x);

		pp.y.ModSub(&_2Gn.x,&pp.x);
		pp.y.ModMulK1(&_s);
		pp.y.ModSub(&_2Gn.y);
		startP = pp;
	}
	delete grp;
	pthread_exit(NULL);
}

void KECCAK_256(uint8_t *source, size_t size,uint8_t *dst)	{
	SHA3_256_CTX ctx;
	SHA3_256_Init(&ctx);
	SHA3_256_Update(&ctx,source,size);
	KECCAK_256_Final(dst,&ctx);
}

void generate_binaddress_eth(Point *publickey,unsigned char *dst_address)	{
	unsigned char bin_publickey[64];
	unsigned char bin_sha256[32];
	size_t pubaddress_size = 50;
	memset(dst_address,0,50);
	publickey->x.Get32Bytes(bin_publickey);
	publickey->y.Get32Bytes(bin_publickey+32);
	KECCAK_256(bin_publickey, 64, dst_address);	
}


void *thread_process_bsgs_dance(void *vargp)	{
	FILE *filekey;
	struct tothread *tt;
	char xpoint_raw[32],*aux_c,*hextemp;
	Int base_key,keyfound;
	Point base_point,point_aux,point_found;
	uint32_t i,j,k,r,salir,thread_number,flip_detector,entrar;
	
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	
	int hLength = (CPU_GRP_SIZE / 2 - 1);
	
	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];

	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Int km,intaux;
	Point pp;
	Point pn;
	grp->Set(dx);

	
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	
	
	entrar = 1;
	
	pthread_mutex_lock(&bsgs_thread);
	switch(rand() % 3)	{
		case 0:	//TOP
			base_key.Set(&n_range_end);
			base_key.Sub(&BSGS_N);
			n_range_end.Sub(&BSGS_N);
			if(base_key.IsLower(&BSGS_CURRENT))	{
				entrar = 0;
			}
			else	{
				n_range_end.Sub(&BSGS_N);
			}
		break;
		case 1: //BOTTOM
			base_key.Set(&BSGS_CURRENT);
			if(base_key.IsGreater(&n_range_end))	{
				entrar = 0;
			}
			else	{
				BSGS_CURRENT.Add(&BSGS_N);
			}
		break;
		case 2: //random - middle
			base_key.Rand(&BSGS_CURRENT,&n_range_end);
		break;
	}
	pthread_mutex_unlock(&bsgs_thread);
	

	intaux.Set(&BSGS_M);
	intaux.Mult(CPU_GRP_SIZE/2);
	
	flip_detector = 1000000;
	
	
	/*
		while base_key is less than n_range_end then:
	*/
	while( entrar )	{
		if(thread_number == 0 && flip_detector == 0)	{
			memorycheck();
			flip_detector = 1000000;
		}
		
		if(FLAGMATRIX)	{
			aux_c = base_key.GetBase16();
			printf("[+] Thread 0x%s \n",aux_c);
			fflush(stdout);
			free(aux_c);
		}
		else	{
			if(FLAGQUIET == 0){
				aux_c = base_key.GetBase16();
				printf("\r[+] Thread 0x%s   \r",aux_c);
				fflush(stdout);
				free(aux_c);
				THREADOUTPUT = 1;
			}
		}
		
		base_point = secp->ComputePublicKey(&base_key);

		km.Set(&base_key);
		km.Neg();
		
		km.Add(&secp->order);
		km.Sub(&intaux);
		point_aux = secp->ComputePublicKey(&km);
		
		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
				if(base_point.equals(OriginalPointsBSGS[k]))	{
					hextemp = base_key.GetBase16();
					printf("[+] Thread Key found privkey %s  \n",hextemp);
					aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],base_point);
					printf("[+] Publickey %s\n",aux_c);
					
					pthread_mutex_lock(&write_keys);
					filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
					if(filekey != NULL)	{
						fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
						fclose(filekey);
					}
					free(hextemp);
					free(aux_c);
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
					startP  = secp->AddDirect(OriginalPointsBSGS[k],point_aux);
					int j = 0;
					while( j < bsgs_aux/1024 && bsgs_found[k]== 0 )	{
					
						int i;
						
						for(i = 0; i < hLength; i++) {
							dx[i].ModSub(&GSn[i].x,&startP.x);
						}
						dx[i].ModSub(&GSn[i].x,&startP.x);  // For the first point
						dx[i+1].ModSub(&_2GSn.x,&startP.x); // For the next center point

						// Grouped ModInv
						grp->ModInv();
						
						/*
						We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
						We compute key in the positive and negative way from the center of the group
						*/

						// center point
						pts[CPU_GRP_SIZE / 2] = startP;
						
						for(i = 0; i<hLength; i++) {

							pp = startP;
							pn = startP;

							// P = startP + i*G
							dy.ModSub(&GSn[i].y,&pp.y);

							_s.ModMulK1(&dy,&dx[i]);        // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
							_p.ModSquareK1(&_s);            // _p = pow2(s)

							pp.x.ModNeg();
							pp.x.ModAdd(&_p);
							pp.x.ModSub(&GSn[i].x);           // rx = pow2(s) - p1.x - p2.x;
							
#if 0
	  pp.y.ModSub(&GSn[i].x,&pp.x);
	  pp.y.ModMulK1(&_s);
	  pp.y.ModSub(&GSn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);  
#endif

							// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
							dyn.Set(&GSn[i].y);
							dyn.ModNeg();
							dyn.ModSub(&pn.y);

							_s.ModMulK1(&dyn,&dx[i]);       // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
							_p.ModSquareK1(&_s);            // _p = pow2(s)

							pn.x.ModNeg();
							pn.x.ModAdd(&_p);
							pn.x.ModSub(&GSn[i].x);          // rx = pow2(s) - p1.x - p2.x;

#if 0
	  pn.y.ModSub(&GSn[i].x,&pn.x);
	  pn.y.ModMulK1(&_s);
	  pn.y.ModAdd(&GSn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);  
#endif


							pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
							pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;

						}

						// First point (startP - (GRP_SZIE/2)*G)
						pn = startP;
						dyn.Set(&GSn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);

						_s.ModMulK1(&dyn,&dx[i]);
						_p.ModSquareK1(&_s);

						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&GSn[i].x);

#if 0
	pn.y.ModSub(&GSn[i].x,&pn.x);
	pn.y.ModMulK1(&_s);
	pn.y.ModAdd(&GSn[i].y);
#endif

						pts[0] = pn;
						
						for(int i = 0; i<CPU_GRP_SIZE && bsgs_found[k]== 0; i++) {
							pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
							r = bloom_check(&bloom_bP,xpoint_raw,32);
							if(r) {
								r = bsgs_secondcheck(&base_key,((j*1024) + i),k,&keyfound);
								if(r)	{
									hextemp = keyfound.GetBase16();
									printf("[+] Thread Key found privkey %s   \n",hextemp);
									point_found = secp->ComputePublicKey(&keyfound);
									aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],point_found);
									printf("[+] Publickey %s\n",aux_c);
									pthread_mutex_lock(&write_keys);
									filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
									if(filekey != NULL)	{
										fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
										fclose(filekey);
									}
									free(hextemp);
									free(aux_c);
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
								} //End if second check
							}//End if first check
							
						}// For for pts variable
						
						// Next start point (startP += (bsSize*GRP_SIZE).G)
						
						pp = startP;
						dy.ModSub(&_2GSn.y,&pp.y);

						_s.ModMulK1(&dy,&dx[i + 1]);
						_p.ModSquareK1(&_s);

						pp.x.ModNeg();
						pp.x.ModAdd(&_p);
						pp.x.ModSub(&_2GSn.x);

						pp.y.ModSub(&_2GSn.x,&pp.x);
						pp.y.ModMulK1(&_s);
						pp.y.ModSub(&_2GSn.y);
						startP = pp;
						
						j++;
					}//while all the aMP points
				}// end else
			}// End if 
		}
			
		steps[thread_number]++;
		flip_detector--;
		
		pthread_mutex_lock(&bsgs_thread);
		switch(rand() % 3)	{
			case 0:	//TOP
				base_key.Set(&n_range_end);
				base_key.Sub(&BSGS_N);
				n_range_end.Sub(&BSGS_N);
				if(base_key.IsLower(&BSGS_CURRENT))	{
					entrar = 0;
				}
				else	{
					n_range_end.Sub(&BSGS_N);
				}
			break;
			case 1: //BOTTOM
				base_key.Set(&BSGS_CURRENT);
				if(base_key.IsGreater(&n_range_end))	{
					entrar = 0;
				}
				else	{
					BSGS_CURRENT.Add(&BSGS_N);
				}
			break;
			case 2: //random - middle
				base_key.Rand(&BSGS_CURRENT,&n_range_end);
			break;
		}
		pthread_mutex_unlock(&bsgs_thread);
		
	}
	ends[thread_number] = 1;
	return NULL;
}

void *thread_process_bsgs_backward(void *vargp)	{
	FILE *filekey;
	struct tothread *tt;
	char xpoint_raw[32],*aux_c,*hextemp;
	Int base_key,keyfound;
	Point base_point,point_aux,point_found;
	uint32_t i,j,k,r,salir,thread_number,flip_detector,entrar;
	
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	
	int hLength = (CPU_GRP_SIZE / 2 - 1);
	
	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];

	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Int km,intaux;
	Point pp;
	Point pn;
	grp->Set(dx);

	
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	

	pthread_mutex_lock(&bsgs_thread);
	n_range_end.Sub(&BSGS_N);
	base_key.Set(&n_range_end);
	
	pthread_mutex_unlock(&bsgs_thread);
	



	
	intaux.Set(&BSGS_M);
	intaux.Mult(CPU_GRP_SIZE/2);
	
	flip_detector = 1000000;
	entrar = 1;
	
	/*
		while base_key is less than n_range_end then:
	*/
	while( entrar )	{
		if(thread_number == 0 && flip_detector == 0)	{
			memorycheck();
			flip_detector = 1000000;
		}
		
		if(FLAGMATRIX)	{
			aux_c = base_key.GetBase16();
			printf("[+] Thread 0x%s \n",aux_c);
			fflush(stdout);
			free(aux_c);
		}
		else	{
			if(FLAGQUIET == 0){
				aux_c = base_key.GetBase16();
				printf("\r[+] Thread 0x%s   \r",aux_c);
				fflush(stdout);
				free(aux_c);
				THREADOUTPUT = 1;
			}
		}
		
		base_point = secp->ComputePublicKey(&base_key);

		km.Set(&base_key);
		km.Neg();
		
		km.Add(&secp->order);
		km.Sub(&intaux);
		point_aux = secp->ComputePublicKey(&km);
		
		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
				if(base_point.equals(OriginalPointsBSGS[k]))	{
					hextemp = base_key.GetBase16();
					printf("[+] Thread Key found privkey %s  \n",hextemp);
					aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],base_point);
					printf("[+] Publickey %s\n",aux_c);
					
					pthread_mutex_lock(&write_keys);
					filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
					if(filekey != NULL)	{
						fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
						fclose(filekey);
					}
					free(hextemp);
					free(aux_c);
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
					startP  = secp->AddDirect(OriginalPointsBSGS[k],point_aux);
					int j = 0;
					while( j < bsgs_aux/1024 && bsgs_found[k]== 0 )	{
					
						int i;
						
						for(i = 0; i < hLength; i++) {
							dx[i].ModSub(&GSn[i].x,&startP.x);
						}
						dx[i].ModSub(&GSn[i].x,&startP.x);  // For the first point
						dx[i+1].ModSub(&_2GSn.x,&startP.x); // For the next center point

						// Grouped ModInv
						grp->ModInv();
						
						/*
						We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
						We compute key in the positive and negative way from the center of the group
						*/

						// center point
						pts[CPU_GRP_SIZE / 2] = startP;
						
						for(i = 0; i<hLength; i++) {

							pp = startP;
							pn = startP;

							// P = startP + i*G
							dy.ModSub(&GSn[i].y,&pp.y);

							_s.ModMulK1(&dy,&dx[i]);        // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
							_p.ModSquareK1(&_s);            // _p = pow2(s)

							pp.x.ModNeg();
							pp.x.ModAdd(&_p);
							pp.x.ModSub(&GSn[i].x);           // rx = pow2(s) - p1.x - p2.x;
							
#if 0
	  pp.y.ModSub(&GSn[i].x,&pp.x);
	  pp.y.ModMulK1(&_s);
	  pp.y.ModSub(&GSn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);  
#endif

							// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
							dyn.Set(&GSn[i].y);
							dyn.ModNeg();
							dyn.ModSub(&pn.y);

							_s.ModMulK1(&dyn,&dx[i]);       // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
							_p.ModSquareK1(&_s);            // _p = pow2(s)

							pn.x.ModNeg();
							pn.x.ModAdd(&_p);
							pn.x.ModSub(&GSn[i].x);          // rx = pow2(s) - p1.x - p2.x;

#if 0
	  pn.y.ModSub(&GSn[i].x,&pn.x);
	  pn.y.ModMulK1(&_s);
	  pn.y.ModAdd(&GSn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);  
#endif


							pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
							pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;

						}

						// First point (startP - (GRP_SZIE/2)*G)
						pn = startP;
						dyn.Set(&GSn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);

						_s.ModMulK1(&dyn,&dx[i]);
						_p.ModSquareK1(&_s);

						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&GSn[i].x);

#if 0
	pn.y.ModSub(&GSn[i].x,&pn.x);
	pn.y.ModMulK1(&_s);
	pn.y.ModAdd(&GSn[i].y);
#endif

						pts[0] = pn;
						
						for(int i = 0; i<CPU_GRP_SIZE && bsgs_found[k]== 0; i++) {
							pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
							r = bloom_check(&bloom_bP,xpoint_raw,32);
							if(r) {
								r = bsgs_secondcheck(&base_key,((j*1024) + i),k,&keyfound);
								if(r)	{
									hextemp = keyfound.GetBase16();
									printf("[+] Thread Key found privkey %s   \n",hextemp);
									point_found = secp->ComputePublicKey(&keyfound);
									aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],point_found);
									printf("[+] Publickey %s\n",aux_c);
									pthread_mutex_lock(&write_keys);
									filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
									if(filekey != NULL)	{
										fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
										fclose(filekey);
									}
									free(hextemp);
									free(aux_c);
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
								} //End if second check
							}//End if first check
							
						}// For for pts variable
						
						// Next start point (startP += (bsSize*GRP_SIZE).G)
						
						pp = startP;
						dy.ModSub(&_2GSn.y,&pp.y);

						_s.ModMulK1(&dy,&dx[i + 1]);
						_p.ModSquareK1(&_s);

						pp.x.ModNeg();
						pp.x.ModAdd(&_p);
						pp.x.ModSub(&_2GSn.x);

						pp.y.ModSub(&_2GSn.x,&pp.x);
						pp.y.ModMulK1(&_s);
						pp.y.ModSub(&_2GSn.y);
						startP = pp;
						
						j++;
					}//while all the aMP points
				}// end else
			}// End if 
		}
			
		steps[thread_number]++;
		flip_detector--;
		
		pthread_mutex_lock(&bsgs_thread);
		n_range_end.Sub(&BSGS_N);
		if(n_range_end.IsLower(&n_range_start))	{
			entrar = 0;
		}
		else	{
			base_key.Set(&n_range_end);
		}
		pthread_mutex_unlock(&bsgs_thread);
	}
	ends[thread_number] = 1;
	return NULL;
}


void *thread_process_bsgs_both(void *vargp)	{
	FILE *filekey;
	struct tothread *tt;
	char xpoint_raw[32],*aux_c,*hextemp;
	Int base_key,keyfound;
	Point base_point,point_aux,point_found;
	uint32_t i,j,k,r,salir,thread_number,flip_detector,entrar;
	
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	
	int hLength = (CPU_GRP_SIZE / 2 - 1);
	
	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];

	Int dy;
	Int dyn;
	Int _s;
	Int _p;
	Int km,intaux;
	Point pp;
	Point pn;
	grp->Set(dx);

	
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);
	
	
	entrar = 1;
	
	pthread_mutex_lock(&bsgs_thread);
	r = rand() % 2;
	if(FLAGDEBUG) printf("[D] was %s\n",r ? "Bottom":"TOP");
	switch(r)	{
		case 0:	//TOP
			base_key.Set(&n_range_end);
			base_key.Sub(&BSGS_N);
			if(base_key.IsLowerOrEqual(&BSGS_CURRENT))	{
				entrar = 0;
			}
			else	{
				n_range_end.Sub(&BSGS_N);
			}
		break;
		case 1: //BOTTOM
			base_key.Set(&BSGS_CURRENT);
			if(base_key.IsGreaterOrEqual(&n_range_end))	{
				entrar = 0;
			}
			else	{
				BSGS_CURRENT.Add(&BSGS_N);
			}
		break;
	}
	pthread_mutex_unlock(&bsgs_thread);
	
	intaux.Set(&BSGS_M);
	intaux.Mult(CPU_GRP_SIZE/2);
	
	flip_detector = 1000000;
	
	
	/*
		while BSGS_CURRENT is less than n_range_end 
	*/
	while( entrar )	{
		
		if(thread_number == 0 && flip_detector == 0)	{
			memorycheck();
			flip_detector = 1000000;
		}
		if(FLAGMATRIX)	{
			aux_c = base_key.GetBase16();
			printf("[+] Thread 0x%s \n",aux_c);
			fflush(stdout);
			free(aux_c);
		}
		else	{
			if(FLAGQUIET == 0){
				aux_c = base_key.GetBase16();
				printf("\r[+] Thread 0x%s   \r",aux_c);
				fflush(stdout);
				free(aux_c);
				THREADOUTPUT = 1;
			}
		}
		
		base_point = secp->ComputePublicKey(&base_key);

		km.Set(&base_key);
		km.Neg();
		
		km.Add(&secp->order);
		km.Sub(&intaux);
		point_aux = secp->ComputePublicKey(&km);
		
		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
				if(base_point.equals(OriginalPointsBSGS[k]))	{
					hextemp = base_key.GetBase16();
					printf("[+] Thread Key found privkey %s  \n",hextemp);
					aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],base_point);
					printf("[+] Publickey %s\n",aux_c);
					
					pthread_mutex_lock(&write_keys);
					filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
					if(filekey != NULL)	{
						fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
						fclose(filekey);
					}
					free(hextemp);
					free(aux_c);
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
					startP  = secp->AddDirect(OriginalPointsBSGS[k],point_aux);
					int j = 0;
					while( j < bsgs_aux/1024 && bsgs_found[k]== 0 )	{
					
						int i;
						
						for(i = 0; i < hLength; i++) {
							dx[i].ModSub(&GSn[i].x,&startP.x);
						}
						dx[i].ModSub(&GSn[i].x,&startP.x);  // For the first point
						dx[i+1].ModSub(&_2GSn.x,&startP.x); // For the next center point

						// Grouped ModInv
						grp->ModInv();
						
						/*
						We use the fact that P + i*G and P - i*G has the same deltax, so the same inverse
						We compute key in the positive and negative way from the center of the group
						*/

						// center point
						pts[CPU_GRP_SIZE / 2] = startP;
						
						for(i = 0; i<hLength; i++) {

							pp = startP;
							pn = startP;

							// P = startP + i*G
							dy.ModSub(&GSn[i].y,&pp.y);

							_s.ModMulK1(&dy,&dx[i]);        // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
							_p.ModSquareK1(&_s);            // _p = pow2(s)

							pp.x.ModNeg();
							pp.x.ModAdd(&_p);
							pp.x.ModSub(&GSn[i].x);           // rx = pow2(s) - p1.x - p2.x;
							
#if 0
	  pp.y.ModSub(&GSn[i].x,&pp.x);
	  pp.y.ModMulK1(&_s);
	  pp.y.ModSub(&GSn[i].y);           // ry = - p2.y - s*(ret.x-p2.x);  
#endif

							// P = startP - i*G  , if (x,y) = i*G then (x,-y) = -i*G
							dyn.Set(&GSn[i].y);
							dyn.ModNeg();
							dyn.ModSub(&pn.y);

							_s.ModMulK1(&dyn,&dx[i]);       // s = (p2.y-p1.y)*inverse(p2.x-p1.x);
							_p.ModSquareK1(&_s);            // _p = pow2(s)

							pn.x.ModNeg();
							pn.x.ModAdd(&_p);
							pn.x.ModSub(&GSn[i].x);          // rx = pow2(s) - p1.x - p2.x;

#if 0
	  pn.y.ModSub(&GSn[i].x,&pn.x);
	  pn.y.ModMulK1(&_s);
	  pn.y.ModAdd(&GSn[i].y);          // ry = - p2.y - s*(ret.x-p2.x);  
#endif


							pts[CPU_GRP_SIZE / 2 + (i + 1)] = pp;
							pts[CPU_GRP_SIZE / 2 - (i + 1)] = pn;

						}

						// First point (startP - (GRP_SZIE/2)*G)
						pn = startP;
						dyn.Set(&GSn[i].y);
						dyn.ModNeg();
						dyn.ModSub(&pn.y);

						_s.ModMulK1(&dyn,&dx[i]);
						_p.ModSquareK1(&_s);

						pn.x.ModNeg();
						pn.x.ModAdd(&_p);
						pn.x.ModSub(&GSn[i].x);

#if 0
	pn.y.ModSub(&GSn[i].x,&pn.x);
	pn.y.ModMulK1(&_s);
	pn.y.ModAdd(&GSn[i].y);
#endif

						pts[0] = pn;
						
						for(int i = 0; i<CPU_GRP_SIZE && bsgs_found[k]== 0; i++) {
							pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
							r = bloom_check(&bloom_bP,xpoint_raw,32);
							if(r) {
								r = bsgs_secondcheck(&base_key,((j*1024) + i),k,&keyfound);
								if(r)	{
									hextemp = keyfound.GetBase16();
									printf("[+] Thread Key found privkey %s   \n",hextemp);
									point_found = secp->ComputePublicKey(&keyfound);
									aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],point_found);
									printf("[+] Publickey %s\n",aux_c);
									pthread_mutex_lock(&write_keys);
									filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
									if(filekey != NULL)	{
										fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
										fclose(filekey);
									}
									free(hextemp);
									free(aux_c);
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
								} //End if second check
							}//End if first check
							
						}// For for pts variable
						
						// Next start point (startP += (bsSize*GRP_SIZE).G)
						
						pp = startP;
						dy.ModSub(&_2GSn.y,&pp.y);

						_s.ModMulK1(&dy,&dx[i + 1]);
						_p.ModSquareK1(&_s);

						pp.x.ModNeg();
						pp.x.ModAdd(&_p);
						pp.x.ModSub(&_2GSn.x);

						pp.y.ModSub(&_2GSn.x,&pp.x);
						pp.y.ModMulK1(&_s);
						pp.y.ModSub(&_2GSn.y);
						startP = pp;
						
						j++;
					}//while all the aMP points
				}// end else
			}// End if 
		}
			
		steps[thread_number]++;
		flip_detector--;
		
		pthread_mutex_lock(&bsgs_thread);
		switch(rand() % 2)	{
			case 0:	//TOP
				base_key.Set(&n_range_end);
				base_key.Sub(&BSGS_N);
				if(base_key.IsLowerOrEqual(&BSGS_CURRENT))	{
					entrar = 0;
				}
				else	{
					n_range_end.Sub(&BSGS_N);
				}
			break;
			case 1: //BOTTOM
				base_key.Set(&BSGS_CURRENT);
				if(base_key.IsGreaterOrEqual(&n_range_end))	{
					entrar = 0;
				}
				else	{
					BSGS_CURRENT.Add(&BSGS_N);
				}
			break;
		}
		pthread_mutex_unlock(&bsgs_thread);
		
	}
	ends[thread_number] = 1;
	return NULL;
}

void memorycheck()	{
	char current_checksum[32];
	char *hextemp,*aux_c;
	if(FLAGDEBUG )printf("[D] Performing Memory checksum  \n");
	sha256((char*)bPtable,bytes,current_checksum);
	if(memcmp(current_checksum,checksum,32) != 0 || memcmp(current_checksum,checksum_backup,32) != 0)	{
		fprintf(stderr,"[E] Memory checksum mismatch, this should not happen but actually happened\nA bit in the memory was flipped by : electrical malfuntion, radiation or a cosmic ray\n");
		hextemp = tohex(current_checksum,32);
		aux_c = tohex(checksum,32);
		fprintf(stderr,"Current Checksum: %s\n",hextemp);
		fprintf(stderr,"Saved Checksum: %s\n",aux_c);
		aux_c = tohex(checksum_backup,32);
		fprintf(stderr,"Backup Checksum: %s\nExit!\n",aux_c);
		exit(0);
	}
}