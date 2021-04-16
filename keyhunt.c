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
	int nt; 		//Number thread
	char *rs; 	//range start
	char *rpt;	//rng per thread
};

struct bPload	{
	int threadid;
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

const char *version = "0.1.20210412 secp256k1";

const char *bloomnames[256] = {"bloom_0","bloom_1","bloom_2","bloom_3","bloom_4","bloom_5","bloom_6","bloom_7","bloom_8","bloom_9","bloom_10","bloom_11","bloom_12","bloom_13","bloom_14","bloom_15","bloom_16","bloom_17","bloom_18","bloom_19","bloom_20","bloom_21","bloom_22","bloom_23","bloom_24","bloom_25","bloom_26","bloom_27","bloom_28","bloom_29","bloom_30","bloom_31","bloom_32","bloom_33","bloom_34","bloom_35","bloom_36","bloom_37","bloom_38","bloom_39","bloom_40","bloom_41","bloom_42","bloom_43","bloom_44","bloom_45","bloom_46","bloom_47","bloom_48","bloom_49","bloom_50","bloom_51","bloom_52","bloom_53","bloom_54","bloom_55","bloom_56","bloom_57","bloom_58","bloom_59","bloom_60","bloom_61","bloom_62","bloom_63","bloom_64","bloom_65","bloom_66","bloom_67","bloom_68","bloom_69","bloom_70","bloom_71","bloom_72","bloom_73","bloom_74","bloom_75","bloom_76","bloom_77","bloom_78","bloom_79","bloom_80","bloom_81","bloom_82","bloom_83","bloom_84","bloom_85","bloom_86","bloom_87","bloom_88","bloom_89","bloom_90","bloom_91","bloom_92","bloom_93","bloom_94","bloom_95","bloom_96","bloom_97","bloom_98","bloom_99","bloom_100","bloom_101","bloom_102","bloom_103","bloom_104","bloom_105","bloom_106","bloom_107","bloom_108","bloom_109","bloom_110","bloom_111","bloom_112","bloom_113","bloom_114","bloom_115","bloom_116","bloom_117","bloom_118","bloom_119","bloom_120","bloom_121","bloom_122","bloom_123","bloom_124","bloom_125","bloom_126","bloom_127","bloom_128","bloom_129","bloom_130","bloom_131","bloom_132","bloom_133","bloom_134","bloom_135","bloom_136","bloom_137","bloom_138","bloom_139","bloom_140","bloom_141","bloom_142","bloom_143","bloom_144","bloom_145","bloom_146","bloom_147","bloom_148","bloom_149","bloom_150","bloom_151","bloom_152","bloom_153","bloom_154","bloom_155","bloom_156","bloom_157","bloom_158","bloom_159","bloom_160","bloom_161","bloom_162","bloom_163","bloom_164","bloom_165","bloom_166","bloom_167","bloom_168","bloom_169","bloom_170","bloom_171","bloom_172","bloom_173","bloom_174","bloom_175","bloom_176","bloom_177","bloom_178","bloom_179","bloom_180","bloom_181","bloom_182","bloom_183","bloom_184","bloom_185","bloom_186","bloom_187","bloom_188","bloom_189","bloom_190","bloom_191","bloom_192","bloom_193","bloom_194","bloom_195","bloom_196","bloom_197","bloom_198","bloom_199","bloom_200","bloom_201","bloom_202","bloom_203","bloom_204","bloom_205","bloom_206","bloom_207","bloom_208","bloom_209","bloom_210","bloom_211","bloom_212","bloom_213","bloom_214","bloom_215","bloom_216","bloom_217","bloom_218","bloom_219","bloom_220","bloom_221","bloom_222","bloom_223","bloom_224","bloom_225","bloom_226","bloom_227","bloom_228","bloom_229","bloom_230","bloom_231","bloom_232","bloom_233","bloom_234","bloom_235","bloom_236","bloom_237","bloom_238","bloom_239","bloom_240","bloom_241","bloom_242","bloom_243","bloom_244","bloom_245","bloom_246","bloom_247","bloom_248","bloom_249","bloom_250","bloom_251","bloom_252","bloom_253","bloom_254","bloom_255"};

std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;

std::vector<Point> GS2n;
Point _2GS2n;

int CPU_GRP_SIZE = 1024;

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
void *thread_process_bsgs_random(void *vargp);
void *thread_bPload(void *vargp);
void *thread_bPloadFile(void *vargp);
void *thread_pub2rmd(void *vargp);

char *publickeytohashrmd160(char *pkey,int length);
char *pubkeytopubaddress(char *pkey,int length);
//char *pubkeytopubaddress_eth(char *pkey,int length);

int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *modes[5] = {"xpoint","address","bsgs","rmd160","pub2rmd"};
const char *cryptos[3] = {"btc","eth","all"};
const char *publicsearch[3] = {"uncompress","compress","both"};
const char *default_filename = "addresses.txt";

pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;

pthread_mutex_t bsgs_thread;

struct bloom dummybloom;
struct bloom bloom;


unsigned int *steps = NULL;
unsigned int *ends = NULL;
uint64_t N = 0;


uint64_t N_SECUENTIAL_MAX = 0xffffffff;
uint64_t DEBUGCOUNT = 0x100000;


Int OUTPUTSECONDS;

int FLAGDEBUG = 0;
int FLAGQUIET = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = -1;
int NTHREADS = 1;

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
int FLAGBLOOMFILTER = 0;

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
std::vector<Point> OriginalPointsBSGS;
bool *OriginalPointsBSGScompressed;


struct bsgs_xvalue *bPtable;
struct address_value *addressTable;
struct bloom bloom_bP[256];
struct bloom bloom_bPx2nd; //Second Bloom filter check
uint64_t bloom_bP_totalbytes = 0;
char *precalculated_p_filename;
uint64_t bsgs_m = 4194304;
uint64_t bsgs_m2;

unsigned long int bsgs_aux;
uint32_t bsgs_point_number;


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


std::vector<Point> BSGS_AMP,BSGS_AMP2;


Point point_temp,point_temp2;	//Temp value for some process

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;


Secp256K1 *secp;

int main(int argc, char **argv)	{
	char buffer[1024];
	char temporal[65];
	char rawvalue[32];
	struct tothread *tt;	//tothread
	Tokenizer t,tokenizerbsgs,tokenizer_xpoint;	//tokenizer
	char *filename,*precalculated_mp_filename,*hextemp,*aux,*aux2,*pointx_str,*pointy_str,*str_seconds,*str_total,*str_pretotal;
	FILE *fd;
	uint64_t j,total_precalculated,i,PERTHREAD,BASE,PERTHREAD_R,itemsbloom,itemsbloom2;
	int readed,s,continue_flag,check_flag,r,lenaux,lendiff,c;
	Int total,pretotal,debugcount_mpz,seconds;
	struct bPload *temp;

	secp = new Secp256K1();
	secp->Init();
	OUTPUTSECONDS.SetInt32(30);
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);
	rseed(clock() + time(NULL));

	printf("[+] Version %s\n",version);

	while ((c = getopt(argc, argv, "dehqRwzb:c:f:g:k:l:m:n:p:r:s:t:v:G:")) != -1) {
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
				printf("-k value\tUse this only with bsgs mode, k value is factor for M, more speed but more RAM use wisely\n");
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
				printf("-z\t\tSave and load bloom bloomfilter from File\n");
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
				switch(indexOf(optarg,modes,5)) {
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
					case MODE_PUB2RMD:
						FLAGMODE = MODE_PUB2RMD;
						printf("[+] Setting mode pub2rmd\n");
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
			case 'z':
			printf("[+] Bloom filter marked to be saved\n");
				FLAGBLOOMFILTER = 1;
			break;
			default:
				printf("[E] Unknow opcion %c\n",c);
			break;
		}
	}
	init_generator();

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
	if(FLAGRANGE) {
		n_range_start.SetBase16(range_start);
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
	if(FLAGMODE != MODE_BSGS)	{
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
		printf("[+] Initializing bloom filter for %" PRIu64 " elements.\n",N);
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
	if(FLAGMODE == MODE_BSGS)	{
		DEBUGCOUNT = N_SECUENTIAL_MAX ;
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

						/* Somebody use this? To be removed 5/Nov */
						/*
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
						*/
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
		/*
		hextemp = BSGS_N.GetBase10();
		printf("[+] BSGS_N: %s\n",hextemp);
		free(hextemp);
		hextemp = BSGS_M.GetBase10();
		printf("[+] BSGS_M: %s\n",hextemp);
		free(hextemp);
		*/
		BSGS_M.SetInt64(bsgs_m);
		//printf("[+] bsgs_m: %"PRIu64"\n",bsgs_m);
		/*
		hextemp = BSGS_N.GetBase10();
		printf("[+] BSGS_N: %s\n",hextemp);
		free(hextemp);
		hextemp = BSGS_M.GetBase10();
		printf("[+] BSGS_M: %s\n",hextemp);
		free(hextemp);
		*/

		if(FLAG_N)	{	//Custom N by the -n param
			BSGS_N.SetInt64(N_SECUENTIAL_MAX);
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
		/*
		hextemp = BSGS_N.GetBase16();
		printf("[+] BSGS_N: %s\n",hextemp);
		free(hextemp);
		hextemp = BSGS_M.GetBase16();
		printf("[+] BSGS_M: %s\n",hextemp);
		free(hextemp);
		*/

		BSGS_AUX.Set(&BSGS_M);
		BSGS_AUX.Mod(&BSGS_GROUP_SIZE);
		if(!BSGS_AUX.IsZero()){
			hextemp = BSGS_GROUP_SIZE.GetBase10();
			fprintf(stderr,"[E] M value is not divisible by %s\n",hextemp);
			exit(0);
		}

		bsgs_m = BSGS_M.GetInt64();
		BSGS_N.Set(&BSGS_M);
		BSGS_N.Mult(&BSGS_M);

		DEBUGCOUNT = bsgs_m * bsgs_m;

		if(FLAGRANGE || FLAGBITRANGE)	{
			if(FLAGBITRANGE)	{	// Bit Range
				n_range_start.SetBase16(bit_range_str_min);
				n_range_end.SetBase16(bit_range_str_max);

				n_range_diff.Set(&n_range_end);
				n_range_diff.Sub(&n_range_start);
				printf("[+] Bit Range %i\n",bitrange);
			}
		}
		else	{	//Random start

			n_range_start.SetInt32(1);
			n_range_end.Set(&secp->order);
			n_range_diff.Rand(&n_range_start,&n_range_end);
			n_range_start.Set(&n_range_diff);
		}
		BSGS_CURRENT.Set(&n_range_start);
		/*
		hextemp = BSGS_N.GetBase16();
		printf("[+] BSGS_N: %s\n",hextemp);
		free(hextemp);
		hextemp = BSGS_M.GetBase16();
		printf("[+] BSGS_M: %s\n",hextemp);
		free(hextemp);
		*/

		if(n_range_diff.IsLower(&BSGS_N) )	{
			BSGS_N.Set(&n_range_diff);

			if(BSGS_N.HasSqrt())	{	//If the root is exact
				BSGS_M.Set(&BSGS_N);
				BSGS_M.ModSqrt();
				/*
				hextemp = BSGS_N.GetBase16();
				printf("[+] BSGS_N: %s\n",hextemp);
				free(hextemp);
				hextemp = BSGS_M.GetBase16();
				printf("[+] BSGS_M: %s\n",hextemp);
				free(hextemp);
				*/
			}
			else	{
				fprintf(stderr,"[E] the range is small and doesn't have exact square root\n");
				exit(0);
			}

			bsgs_m = BSGS_M.GetInt64();
			BSGS_N.Set(&BSGS_M);
			BSGS_N.Mult(&BSGS_M);


			DEBUGCOUNT = bsgs_m * bsgs_m;
			bsgs_m = BSGS_M.GetInt64();
			DEBUGCOUNT = (uint64_t)((uint64_t)bsgs_m * (uint64_t)bsgs_m);
		}

		BSGS_M.Mult((uint64_t)KFACTOR);
		BSGS_AUX.SetInt32(20);
		BSGS_R.Set(&BSGS_M);
		BSGS_R.Mod(&BSGS_AUX);
		BSGS_M2.Set(&BSGS_M);
		BSGS_M2.Div(&BSGS_AUX);

		if(!BSGS_R.IsZero())	{

			BSGS_M2.AddOne();
		}


		bsgs_m2 =  BSGS_M2.GetInt64();
		BSGS_AUX.Set(&BSGS_N);
		BSGS_AUX.Div(&BSGS_M);
		BSGS_R.Set(&BSGS_N);
		BSGS_R.Mod(&BSGS_M);

		if(!BSGS_R.IsZero())	{
			BSGS_N.Set(&BSGS_M);
			BSGS_N.Mult(&BSGS_AUX);
		}

		bsgs_m = (uint64_t)((uint64_t) bsgs_m * (uint64_t)KFACTOR);
		bsgs_aux = BSGS_AUX.GetInt64();
		DEBUGCOUNT = (uint64_t)((uint64_t)bsgs_m * (uint64_t)bsgs_aux);

		printf("[+] Setting N up to %" PRIu64 ".\n",DEBUGCOUNT);

		itemsbloom = ((uint64_t)(bsgs_m/256)) > 10000 ? (uint64_t)(bsgs_m/256) : 10000;
		itemsbloom2 = bsgs_m2 > 1000 ? bsgs_m : 10000;

		if( FLAGBLOOMFILTER == 1	)	{
			int continuebloom = 1;
			int numberbloom = 0;
			for(i=0; i< 256 && continuebloom; i++)	{
				if(bloom_loadcustom(&bloom_bP[i],(char*)bloomnames[i])	== 1){
					continuebloom = 0;
				}
				else	{
					if(bloom_dummy(&dummybloom,itemsbloom,0.000001)	== 0){
						numberbloom++;
						if(dummybloom.bytes != bloom_bP[i].bytes)	{
							continuebloom = 0;
						}
					}
					else	{
						continuebloom = 0;
					}
				}
			}
			if(continuebloom == 1)	{
				if(bloom_loadcustom(&bloom_bPx2nd,(char*)"bPx2nd")	== 1)	{
					continuebloom == 0;
				}
				else	{
					if(bloom_dummy(&dummybloom,itemsbloom2,0.000001)	== 0){
						if(dummybloom.bytes != bloom_bPx2nd.bytes)	{
							continuebloom = 0;
						}
						if(continuebloom == 0)	{
							bloom_free(&bloom_bPx2nd);
						}
					}
				}
			}
			if(continuebloom == 0)	{
				fprintf(stderr,"[E] Some bloom file fail or missmatch size\n");
				FLAGBLOOMFILTER = 0;
				for(i=0; i < numberbloom ; i++)	{
					bloom_free(&bloom_bP[i]);
				}
			}
		}



/*
		if( FLAGBLOOMFILTER == 0)	{
*/
		for(i=0; i< 256; i++)	{
			if(bloom_init2(&bloom_bP[i],itemsbloom,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init [%" PRIu64 "]\n",i);
				exit(0);
			}
			bloom_bP_totalbytes += bloom_bP[i].bytes;
			if(FLAGDEBUG) bloom_print(&bloom_bP[i]);
		}
		printf("[+] Init 1st bloom filter for %lu elements : %.2f MB\n",bsgs_m,(float)((uint64_t)bloom_bP_totalbytes/(uint64_t)1048576));

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
		printf("[+] Init 2nd bloom filter for %lu elements : %.2f MB\n",bsgs_m2,(double)((double)bloom_bPx2nd.bytes/(double)1048576));
		//bloom_print(&bloom_bPx2nd);
		/*
		hextemp = BSGS_M.GetBase16();
		printf("[+] BSGS_M: %s\n",hextemp);
		free(hextemp);
		hextemp = BSGS_M2.GetBase16();
		printf("[+] BSGS_M2: %s\n",hextemp);
		free(hextemp);
		*/

		BSGS_MP = secp->ComputePublicKey(&BSGS_M);
		BSGS_MP2 = secp->ComputePublicKey(&BSGS_M2);


		printf("[+] Allocating %.1f MB for %" PRIu64 " aMP Points\n",(double)(((double)(bsgs_aux*sizeof(Point)))/(double)1048576),bsgs_aux);
		i = 0;
		BSGS_AMP.reserve(bsgs_aux);
		//printf("[+] Allocating %.1f MB for aMP Points (2nd)\n",(float)(((uint64_t)(bsgs_m2*sizeof(struct strPoint)))/(uint64_t)1048576));
		BSGS_AMP2.reserve(bsgs_m2);

		i= 0;
		if(FLAGPRECALCUTED_MP_FILE)	{
			printf("[+] Reading aMP points from file %s\n",precalculated_mp_filename);
			fd = fopen(precalculated_mp_filename,"rb");
			if(fd != NULL)	{
				while(!feof(fd) && i < bsgs_aux )	{
					if(fread(temporal,1,64,fd) == 64)	{
						BSGS_AMP[i].x.Set32Bytes((unsigned char*)temporal);
						BSGS_AMP[i].x.Set32Bytes((unsigned char*)(temporal+32));
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
				point_temp.Set(BSGS_MP);
				for(i = 0; i < bsgs_aux; i++)	{
					BSGS_AMP[i] = secp->Negation(point_temp);
					if(i == 0)	{
						printf("\n[+] point_temp vs BSGS_MP %s\n",point_temp.equals(BSGS_MP) ? "Si iguales":"No, diferentes");
					}
					if(point_temp.equals(BSGS_MP))	{
						point_temp2 = secp->DoubleDirect(BSGS_MP);
					}
					else	{
						point_temp2 = secp->AddDirect(point_temp,BSGS_MP);
					}
					point_temp.Set(point_temp2);
				}
			}
		}
		else	{
			printf("[+] Precalculating %" PRIu64 " aMP points\n",bsgs_aux);
			point_temp.Set(BSGS_MP);
			for(i = 0; i < bsgs_aux; i++)	{
				BSGS_AMP[i] = secp->Negation(point_temp);
				if(i == 0)	{
					point_temp2 = secp->DoubleDirect(BSGS_MP);
				}
				else	{
					point_temp2 = secp->AddDirect(point_temp,BSGS_MP);
				}
				point_temp.Set(point_temp2);
			}
		}

		point_temp.Set(BSGS_MP2);
		for(i = 0; i < 20; i++)	{
			BSGS_AMP2[i] = secp->Negation(point_temp);
			if(i == 0)	{
				point_temp2 = secp->DoubleDirect(BSGS_MP2);
			}
			else	{
				point_temp2 = secp->AddDirect(point_temp,BSGS_MP2);
			}
			point_temp.Set(point_temp2);
		}
		printf("[+] Allocating %.2f MB for %" PRIu64  " bP Points\n",(double)((double)((uint64_t)bsgs_m2*(uint64_t)sizeof(struct bsgs_xvalue))/(double)1048576),bsgs_m2);
		//printf("[+] Allocating %.2f MB for bP Points\n",(float)((uint64_t)((uint64_t)bsgs_m*(uint64_t)sizeof(struct bsgs_xvalue))/(uint64_t)1048576));
		bPtable = (struct bsgs_xvalue*) calloc(bsgs_m2,sizeof(struct bsgs_xvalue));
		if(bPtable == NULL)	{
			printf("[E] error malloc()\n");
			exit(0);
		}
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

		printf("[+] Sorting %lu elements... ",bsgs_m2);
		bsgs_sort(bPtable,bsgs_m2);
		printf("Done!\n");

		i = 0;

		steps = (unsigned int *) calloc(NTHREADS,sizeof(int));
		ends = (unsigned int *) calloc(NTHREADS,sizeof(int));
		tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
		DEBUGCOUNT = (uint64_t)((uint64_t)bsgs_m * (uint64_t)bsgs_aux);
		for(i= 0;i < NTHREADS; i++)	{
			tt = (tothread*) malloc(sizeof(struct tothread));
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
	continue_flag = 1;
	total.SetInt32(0);
	pretotal.SetInt32(0);
	debugcount_mpz.SetInt64(DEBUGCOUNT);
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
				pretotal.Set(&total);
				pretotal.Div(&seconds);
				str_seconds = seconds.GetBase10();
				str_pretotal = pretotal.GetBase10();
				str_total = total.GetBase10();
				pthread_mutex_lock(&bsgs_thread);
				if(THREADOUTPUT == 1)	{
					sprintf(buffer,"\nTotal %s keys in %s seconds: %s keys/s\r",str_total,str_seconds,str_pretotal);
				}
				else	{
					sprintf(buffer,"\rTotal %s keys in %s seconds: %s keys/s\r",str_total,str_seconds,str_pretotal);
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
	uint64_t i,j;
	Point R,temporal;
	uint64_t count = 0;
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
			if(n_range_start.IsLower(&n_range_end)){
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

				if(FLAGQUIET == 0){
					hextemp = key_mpz.GetBase16();
					printf("\rBase key: %s     ",hextemp);
					fflush(stdout);
					free(hextemp);
					THREADOUTPUT = 1;
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
					//temporal.Set(R);
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
										hextemp = (char*) malloc(65);
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
					if(count %	DEBUGCOUNT == 0)	{
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
	Point base_point,point_aux,point_aux2,point_found,BSGS_S,BSGS_Q,BSGS_Q_AMP;
	uint32_t i,j,k,r,salir,thread_number,bloom_counter =0;
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
	/*
		while base_key is less than n_range_end then:
	*/
	while(base_key.IsLower(&n_range_end) )	{
		//gmp_printf("While cycle: base_key : %Zd < n_range_end: %Zd\n",base_key,n_range_end);
		if(FLAGQUIET == 0){
			aux_c = base_key.GetBase16();
			printf("\r[+] Thread  %s   ",aux_c);
			fflush(stdout);
			free(aux_c);
			THREADOUTPUT = 1;
		}
		/*
			Set base_point in to base_key * G
			base_point = base_key * G
		*/
	//	printf("[D] bsgs_point_number %u\n",bsgs_point_number);
		base_point = secp->ComputePublicKey(&base_key);
		/*
			We are going to need -( base_point * G)
			point_aux = -( base_point * G)
		*/
		point_aux = secp->Negation(base_point);
		/*
		hextemp = secp->GetPublicKeyHex(false,point_aux);
		printf("point_aux %s\n",hextemp);
		free(hextemp);
		hextemp = secp->GetPublicKeyHex(false,base_point);
		printf("base_point %s\n",hextemp);
		free(hextemp);
		*/

		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
				/*reset main variabler before the do-while cicle*/
				/* Main cycle
					for every a in 0 to bsgs_m
				*/
				salir = 0;
				i = 0;
				BSGS_Q = secp->AddDirect(OriginalPointsBSGS[k],point_aux);
				BSGS_S.Set(BSGS_Q);

				do {
					/*
					if(i ==  52428 || i == 0 || i == 1)	{
						aux_c = secp->GetPublicKeyHex(false,BSGS_S);
						hextemp = secp->GetPublicKeyHex(false,BSGS_AMP[i]);
						printf("\r[d] Debug: %s : %u\n",aux_c,i);
						printf("[d] Debug: BSGS_AMP %s : %u\n",hextemp,i);
						free(aux_c);
						free(hextemp);
					}
					*/
					/* We need to test individually every point in BSGS_Q */
					/*Extract BSGS_S.x into xpoint_raw*/
					BSGS_S.x.Get32Bytes((unsigned char*)xpoint_raw);

					/* Lookup for the xpoint_raw into the bloom filter*/

					r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])],xpoint_raw,32);
					if(r) {
						bloom_counter++;
						/* Lookup for the xpoint_raw into the full sorted list*/
						//r = bsgs_searchbinary(bPtable,xpoint_raw,bsgs_m,&j);
						r = bsgs_secondcheck(&base_key,i,k,&keyfound);

						if(r)	{
							hextemp = keyfound.GetBase16();
							printf("\n[+] Thread Key found privkey %s\n",hextemp);
							point_aux2 = secp->ComputePublicKey(&keyfound);
							aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],point_aux2);

							printf("[+] Publickey %s\n",aux_c);
							pthread_mutex_lock(&write_keys);
							filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
							if(filekey != NULL)	{
								fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
								fclose(filekey);
							}
							pthread_mutex_unlock(&write_keys);
							free(hextemp);
							free(aux_c);
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
					BSGS_Q_AMP = secp->AddDirect(BSGS_Q,BSGS_AMP[i]);
					BSGS_S.Set(BSGS_Q_AMP);
					i++;
				}while( i < bsgs_aux && !bsgs_found[k]);
			} //end if
		}// End for
		steps[thread_number]++;
		pthread_mutex_lock(&bsgs_thread);
		base_key.Set(&BSGS_CURRENT);
		BSGS_CURRENT.Add(&BSGS_N);
		pthread_mutex_unlock(&bsgs_thread);

		if(FLAGDEBUG ) printf("%u of %" PRIu64 "\n",bloom_counter,(uint64_t)(bsgs_aux*bsgs_point_number));
		bloom_counter = 0;
	}
	ends[thread_number] = 1;
	return NULL;
}

void *thread_process_bsgs_random(void *vargp)	{
	FILE *filekey;
	struct tothread *tt;
	char xpoint_raw[32],*aux_c,*hextemp;
	Int base_key,keyfound,n_range_random;
	Point base_point,point_aux,point_aux2,point_found,BSGS_S,BSGS_Q,BSGS_Q_AMP;
	uint32_t i,j,k,r,salir,thread_number,bloom_counter = 0;
	tt = (struct tothread *)vargp;
	thread_number = tt->nt;
	free(tt);

	pthread_mutex_lock(&bsgs_thread);
	/*			| Start Range	 | End Range		|
		None	| 1							|	EC.N				 |
-b	bit		| Min bit value |Max bit value |
-r	A:B	 | A						 | B 					 |
	*/
	// set base_key = random(end_range - start range)
	base_key.Rand(&n_range_start,&n_range_end);
	pthread_mutex_unlock(&bsgs_thread);
	/*
		while base_key is less than n_range_end then:
	*/
	while(base_key.IsLower(&n_range_end))	{
		//gmp_printf("While cycle: base_key : %Zd < n_range_end: %Zd\n",base_key,n_range_end);
		if(FLAGQUIET == 0){
			aux_c = base_key.GetBase16();
			printf("\r[+] Thread %s",aux_c);
			fflush(stdout);
			free(aux_c);
			THREADOUTPUT = 1;
		}
		/*
			Set base_point in to base_key * G
			base_point = base_key * G
		*/
		base_point = secp->ComputePublicKey(&base_key);
		/*
			We are going to need -( base_point * G)
			point_aux = -( base_point * G)
		*/
		point_aux = secp->Negation(base_point);



		/* We need to test individually every point in BSGS_Q */
		for(k = 0; k < bsgs_point_number ; k++)	{
			if(bsgs_found[k] == 0)	{
			/*reset main variables before the do-while cicle*/
			salir = 0;
			i = 0;
			/* Main cycle for every a in 0 to bsgs_aux
			*/
			BSGS_Q = secp->AddDirect(OriginalPointsBSGS[k],point_aux);
			BSGS_S.Set(BSGS_Q);
			do {
					BSGS_S.x.Get32Bytes((unsigned char*)xpoint_raw);
					r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])],xpoint_raw,32);
					if(r) {
						bloom_counter++;
						/* Lookup for the xpoint_raw into the full sorted list*/
						r = bsgs_secondcheck(&base_key,i,k,&keyfound);
						if(r)	{
							hextemp = keyfound.GetBase16();
							printf("\n[+] Thread Key found privkey %s\n",hextemp);
							point_aux2 = secp->ComputePublicKey(&keyfound);
							aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed[k],point_aux2);
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
					}
					BSGS_Q_AMP = secp->AddDirect(BSGS_AMP[i],BSGS_Q);
					BSGS_S.Set(BSGS_Q_AMP);
					i++;
				} while( i < bsgs_aux && !bsgs_found[k]);
			}	//End if
		} // End for with k bsgs_point_number
		steps[thread_number]++;
		pthread_mutex_lock(&bsgs_thread);
		base_key.Rand(&n_range_start,&n_range_end);
		pthread_mutex_unlock(&bsgs_thread);
		if(FLAGDEBUG ) printf("%u of %" PRIu64 "\n",bloom_counter,(uint64_t)(bsgs_aux*bsgs_point_number));
		bloom_counter = 0;
	}
	ends[thread_number] = 1;
	return NULL;
}

/*
	The bsgs_secondcheck function is made to perform a second BSGS search in a Range of less size.
	This funtion is made with the especific purpouse to USE a smaller bPTable in RAM.
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
				memcpy(bPtable[j].value,rawvalue+16,BSGS_XVALUE_RAM);
				bPtable[j].index = j;
				bloom_add(&bloom_bPx2nd, rawvalue, BSGS_BUFFERXPOINTLENGTH);
				j++;
			}
			bloom_add(&bloom_bP[((uint8_t)rawvalue[0])], rawvalue ,BSGS_BUFFERXPOINTLENGTH);
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
			if(FLAGQUIET == 0)	{
				temphex = tohex((char*)&pub,33);
				printf("\r[+] Thread %s",temphex);
				fflush(stdout);
				THREADOUTPUT = 1;
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
	} while(pub2rmd_continue);
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
				memcpy(bPtable[j_counter].value,rawvalue+16,BSGS_XVALUE_RAM);
				bPtable[j_counter].index = j_counter;
				bloom_add(&bloom_bPx2nd, rawvalue, BSGS_BUFFERXPOINTLENGTH);
				j_counter++;
			}
			if(i_counter < tt->to)	{
				bloom_add(&bloom_bP[((uint8_t)rawvalue[0])], rawvalue ,BSGS_BUFFERXPOINTLENGTH);
				tt->counter++;
			}
			i_counter++;
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
