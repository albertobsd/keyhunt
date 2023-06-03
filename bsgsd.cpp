/*
Develop by Alberto
email: albertobsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <vector>
#include <inttypes.h>
#include "base58/libbase58.h"
#include "rmd160/rmd160.h"
#include "oldbloom/oldbloom.h"
#include "bloom/bloom.h"
#include "sha3/sha3.h"
#include "util.h"

#include "secp256k1/SECP256k1.h"
#include "secp256k1/Point.h"
#include "secp256k1/Int.h"
#include "secp256k1/IntGroup.h"
#include "secp256k1/Random.h"

#include "hash/sha256.h"
#include "hash/ripemd160.h"

#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>
#include <linux/random.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // for inet_addr()
#include <pthread.h>   // for pthread functions

#define PORT 8080
#define BUFFER_SIZE 1024



#define MODE_BSGS 2


uint32_t THREADBPWORKLOAD = 1048576;

struct checksumsha256	{
	char data[32];
	char backup[32];
};

struct bsgs_xvalue	{
	uint8_t value[6];
	uint64_t index;
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
	uint64_t workload;
	uint32_t aux;
	uint32_t finished;
};


	
const char *version = "0.2.230519 Satoshi Quest";
const char *ip_default = "127.0.0.1";

char *IP;
int port;

#define CPU_GRP_SIZE 1024

std::vector<Point> Gn;
Point _2Gn;

std::vector<Point> GSn;
Point _2GSn;


void menu();
void init_generator();

int sendstr(int client_fd,const char *str);

void sleep_ms(int milliseconds);

void bsgs_sort(struct bsgs_xvalue *arr,int64_t n);
void bsgs_myheapsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_insertionsort(struct bsgs_xvalue *arr, int64_t n);
void bsgs_introsort(struct bsgs_xvalue *arr,uint32_t depthLimit, int64_t n);
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b);
void bsgs_heapify(struct bsgs_xvalue *arr, int64_t n, int64_t i);
int64_t bsgs_partition(struct bsgs_xvalue *arr, int64_t n);

int bsgs_searchbinary(struct bsgs_xvalue *arr,char *data,int64_t array_length,uint64_t *r_value);
int bsgs_secondcheck(Int *start_range,uint32_t a,Int *privatekey);
int bsgs_thirdcheck(Int *start_range,uint32_t a,Int *privatekey);


void writekey(bool compressed,Int *key);
void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line);

void* client_handler(void* arg);


void calcualteindex(int i,Int *key);

void *thread_process_bsgs(void *vargp);
void *thread_bPload(void *vargp);
void *thread_bPload_2blooms(void *vargp);

char *publickeytohashrmd160(char *pkey,int length);
void publickeytohashrmd160_dst(char *pkey,int length,char *dst);
char *pubkeytopubaddress(char *pkey,int length);
void pubkeytopubaddress_dst(char *pkey,int length,char *dst);
void rmd160toaddress_dst(char *rmd,char *dst);



int THREADOUTPUT = 0;
char *bit_range_str_min;
char *bit_range_str_max;

const char *bsgs_modes[5] = {"secuential","backward","both","random","dance"};

pthread_t *tid = NULL;
pthread_mutex_t write_keys;
pthread_mutex_t write_random;
pthread_mutex_t mutex_bsgs_thread;
pthread_mutex_t *bPload_mutex;

uint64_t FINISHED_THREADS_COUNTER = 0;
uint64_t FINISHED_THREADS_BP = 0;
uint64_t THREADCYCLES = 0;
uint64_t THREADCOUNTER = 0;
uint64_t FINISHED_ITEMS = 0;
uint64_t OLDFINISHED_ITEMS = -1;

uint8_t byte_encode_crypto = 0x00;		/* Bitcoin  */



struct bloom bloom;

uint64_t N = 0;

uint64_t N_SECUENTIAL_MAX = 0x100000000;
uint64_t DEBUGCOUNT = 0x400;
uint64_t u64range;


Int BSGSkeyfound;

int FLAGSKIPCHECKSUM = 0;
int FLAGBSGSMODE = 0;
int FLAGDEBUG = 0;
int KFACTOR = 1;
int MAXLENGTHADDRESS = 20;
int NTHREADS = 1;

int FLAGSAVEREADFILE = 1;
int FLAGREADEDFILE1 = 0;
int FLAGREADEDFILE2 = 0;
int FLAGREADEDFILE3 = 0;
int FLAGREADEDFILE4 = 0;
int FLAGUPDATEFILE1 = 0;


int FLAGBITRANGE = 0;
int FLAGRANGE = 0;
int FLAGMODE = MODE_BSGS;
int FLAG_N = 0;

int bitrange;
char *str_N;
char *range_start;
char *range_end;
char *str_stride;
Int stride;

uint64_t BSGS_XVALUE_RAM = 6;
uint64_t BSGS_BUFFERXPOINTLENGTH = 32;
uint64_t BSGS_BUFFERREGISTERLENGTH = 36;

/*
BSGS Variables
*/
int bsgs_found;
Point OriginalPointsBSGS;
bool OriginalPointsBSGScompressed;

uint64_t bytes;
char checksum[32],checksum_backup[32];
char buffer_bloom_file[1024];
struct bsgs_xvalue *bPtable;

struct oldbloom oldbloom_bP;

struct bloom *bloom_bP;
struct bloom *bloom_bPx2nd; //2nd Bloom filter check
struct bloom *bloom_bPx3rd; //3rd Bloom filter check

struct checksumsha256 *bloom_bP_checksums;
struct checksumsha256 *bloom_bPx2nd_checksums;
struct checksumsha256 *bloom_bPx3rd_checksums;

pthread_mutex_t *bloom_bP_mutex;
pthread_mutex_t *bloom_bPx2nd_mutex;
pthread_mutex_t *bloom_bPx3rd_mutex;




uint64_t bloom_bP_totalbytes = 0;
uint64_t bloom_bP2_totalbytes = 0;
uint64_t bloom_bP3_totalbytes = 0;
uint64_t bsgs_m = 4194304;
uint64_t bsgs_m2;
uint64_t bsgs_m3;
unsigned long int bsgs_aux;
//int32_t bsgs_point_number;

const char *str_limits_prefixs[7] = {"Mkeys/s","Gkeys/s","Tkeys/s","Pkeys/s","Ekeys/s","Zkeys/s","Ykeys/s"};
const char *str_limits[7] = {"1000000","1000000000","1000000000000","1000000000000000","1000000000000000000","1000000000000000000000","1000000000000000000000000"};
Int int_limits[7];




Int BSGS_GROUP_SIZE;
Int BSGS_CURRENT;
Int BSGS_R;
Int BSGS_AUX;
Int BSGS_N;
Int BSGS_M;					//M is squareroot(N)
Int BSGS_M_double;
Int BSGS_M2;				//M2 is M/32
Int BSGS_M2_double;			//M2_double is M2 * 2

Int BSGS_M3;				//M3 is M2/32
Int BSGS_M3_double;			//M3_double is M3 * 2


Int ONE;
Int ZERO;
Int MPZAUX;

Point BSGS_P;			//Original P is actually G, but this P value change over time for calculations
Point BSGS_MP;			//MP values this is m * P
Point BSGS_MP2;			//MP2 values this is m2 * P
Point BSGS_MP3;			//MP3 values this is m3 * P


Point BSGS_MP_double;			//MP2 values this is m2 * P * 2
Point BSGS_MP2_double;			//MP2 values this is m2 * P * 2
Point BSGS_MP3_double;			//MP3 values this is m3 * P * 2


std::vector<Point> BSGS_AMP2;
std::vector<Point> BSGS_AMP3;

Point point_temp,point_temp2;	//Temp value for some process

Int n_range_start;
Int n_range_end;
Int n_range_diff;
Int n_range_aux;


Secp256K1 *secp;

int main(int argc, char **argv)	{
	// File pointers
	FILE *fd_aux1, *fd_aux2, *fd_aux3;

	// Strings
	char *hextemp = NULL;
	char *bf_ptr = NULL;
	char *bPload_threads_available;

	// Buffers
	char rawvalue[32];

	// 64-bit integers
	uint64_t BASE, PERTHREAD_R, itemsbloom, itemsbloom2, itemsbloom3;

	// 32-bit integers
	uint32_t finished;
	int readed, c, salir,i,s;

	// Custom integers
	Int total, pretotal, debugcount_mpz, seconds, div_pretotal, int_aux, int_r, int_q, int58;

	// Pointers
	struct bPload *bPload_temp_ptr;

	// Sizes
	size_t rsize;

	
	pthread_mutex_init(&write_keys,NULL);
	pthread_mutex_init(&write_random,NULL);
	pthread_mutex_init(&mutex_bsgs_thread,NULL);

	srand(time(NULL));

	secp = new Secp256K1();
	secp->Init();
	ZERO.SetInt32(0);
	ONE.SetInt32(1);
	BSGS_GROUP_SIZE.SetInt32(CPU_GRP_SIZE);
	
	unsigned long rseedvalue;
	int bytes_read = getrandom(&rseedvalue, sizeof(unsigned long), GRND_NONBLOCK);
	if(bytes_read > 0)	{
		rseed(rseedvalue);
		/*
		In any case that seed is for a failsafe RNG, the default source on linux is getrandom function
		See https://www.2uo.de/myths-about-urandom/
		*/
	}
	else	{
		/*
			what year is??
			WTF linux without RNG ? 
		*/
		fprintf(stderr,"[E] Error getrandom() ?\n");
		exit(0);
		rseed(clock() + time(NULL) + rand()*rand());
	}
	
	port = PORT;
	IP = (char*)ip_default;
	
	
	printf("[+] Version %s, developed by AlbertoBSD\n",version);

	while ((c = getopt(argc, argv, "6hk:n:t:p:i:")) != -1) {
		switch(c) {
			case '6':
				FLAGSKIPCHECKSUM = 1;
				fprintf(stderr,"[W] Skipping checksums on files\n");
			break;
			case 'h':
				// Show help menu
				menu();
			break;
			case 'k':
				// Set KFACTOR
				KFACTOR = (int)strtol(optarg,NULL,10);
				if(KFACTOR <= 0)	{
					KFACTOR = 1;
				}
				printf("[+] K factor %i\n",KFACTOR);
			break;
			case 'n':
				// Set FLAG_N and str_N
				FLAG_N = 1;
				str_N = optarg;
			break;
			case 't':
				// Set number of threads (NTHREADS)
				NTHREADS = strtol(optarg,NULL,10);
				if(NTHREADS <= 0)	{
					NTHREADS = 1;
				}
				printf((NTHREADS > 1) ? "[+] Threads : %u\n": "[+] Thread : %u\n",NTHREADS);
			break;
			case 'p':
				port = (int) strtol(optarg,NULL,10);
				if(port <= 0  || port > 65535 )	{
					port = PORT;
				}
			break;
			case 'i':
				IP = optarg;
			break;
			default:
				// Handle unknown options
				fprintf(stderr,"[E] Unknow opcion -%c\n",c);
				exit(0);
			break;
		}
	}

	


	stride.Set(&ONE);
	init_generator();
	
	if(FLAGMODE == MODE_BSGS )	{
		printf("[+] Mode BSGS %s\n",bsgs_modes[FLAGBSGSMODE]);
	}
	
	
	if(FLAGMODE == MODE_BSGS )	{
		
		BSGS_N.SetInt32(0);
		BSGS_M.SetInt32(0);
		

		BSGS_M.SetInt64(bsgs_m);


		if(FLAG_N)	{	//Custom N by the -n param
						
			/* Here we need to validate if the given string is a valid hexadecimal number or a base 10 number*/
			
			/* Now the conversion*/
			if(str_N[0] == '0' && (str_N[1] == 'x' || str_N[1] == 'X'))	{	/*We expected a hexadecimal value after 0x  -> str_N +2 */
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
	
		/*
	M	2199023255552
		109951162777.6
	M2	109951162778
		5497558138.9
	M3	5497558139
		*/

		BSGS_M.Mult((uint64_t)KFACTOR);
		BSGS_AUX.SetInt32(32);
		BSGS_R.Set(&BSGS_M);
		BSGS_R.Mod(&BSGS_AUX);
		BSGS_M2.Set(&BSGS_M);
		BSGS_M2.Div(&BSGS_AUX);

		if(!BSGS_R.IsZero())	{ /* If BSGS_M modulo 32 is not 0*/
			BSGS_M2.AddOne();
		}
		
		BSGS_M_double.SetInt32(2);
		BSGS_M_double.Mult(&BSGS_M);
		
		
		BSGS_M2_double.SetInt32(2);
		BSGS_M2_double.Mult(&BSGS_M2);
		
		BSGS_R.Set(&BSGS_M2);
		BSGS_R.Mod(&BSGS_AUX);
		
		
		
		BSGS_M3.Set(&BSGS_M2);
		BSGS_M3.Div(&BSGS_AUX);
		
		if(!BSGS_R.IsZero())	{ /* If BSGS_M2 modulo 32 is not 0*/
			BSGS_M3.AddOne();
		}
		
		BSGS_M3_double.SetInt32(2);
		BSGS_M3_double.Mult(&BSGS_M3);
		
		bsgs_m2 =  BSGS_M2.GetInt64();
		bsgs_m3 =  BSGS_M3.GetInt64();
		
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
		bsgs_m = BSGS_M.GetInt64();
		free(hextemp);


		
		if(((uint64_t)(bsgs_m/256)) > 10000)	{
			itemsbloom = (uint64_t)(bsgs_m / 256);
			if(bsgs_m % 256 != 0 )	{
				itemsbloom++;
			}
		}
		else{
			itemsbloom = 1000;
		}
		
		if(((uint64_t)(bsgs_m2/256)) > 1000)	{
			itemsbloom2 = (uint64_t)(bsgs_m2 / 256);
			if(bsgs_m2 % 256 != 0)	{
				itemsbloom2++;
			}
		}
		else	{
			itemsbloom2 = 1000;
		}
		
		if(((uint64_t)(bsgs_m3/256)) > 1000)	{
			itemsbloom3 = (uint64_t)(bsgs_m3/256);
			if(bsgs_m3 % 256 != 0 )	{
				itemsbloom3++;
			}
		}
		else	{
			itemsbloom3 = 1000;
		}
		
		printf("[+] Bloom filter for %" PRIu64 " elements ",bsgs_m);
		bloom_bP = (struct bloom*)calloc(256,sizeof(struct bloom));
		checkpointer((void *)bloom_bP,__FILE__,"calloc","bloom_bP" ,__LINE__ -1 );
		bloom_bP_checksums = (struct checksumsha256*)calloc(256,sizeof(struct checksumsha256));
		checkpointer((void *)bloom_bP_checksums,__FILE__,"calloc","bloom_bP_checksums" ,__LINE__ -1 );
		
		bloom_bP_mutex = (pthread_mutex_t*) calloc(256,sizeof(pthread_mutex_t));
		checkpointer((void *)bloom_bP_mutex,__FILE__,"calloc","bloom_bP_mutex" ,__LINE__ -1 );
		

		fflush(stdout);
		bloom_bP_totalbytes = 0;
		for(i=0; i< 256; i++)	{
			pthread_mutex_init(&bloom_bP_mutex[i],NULL);
			if(bloom_init2(&bloom_bP[i],itemsbloom,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init _ %i\n",i);
				exit(0);
			}
			bloom_bP_totalbytes += bloom_bP[i].bytes;
		}
		printf(": %.2f MB\n",(float)((float)(uint64_t)bloom_bP_totalbytes/(float)(uint64_t)1048576));


		printf("[+] Bloom filter for %" PRIu64 " elements ",bsgs_m2);
		
		bloom_bPx2nd_mutex = (pthread_mutex_t*) calloc(256,sizeof(pthread_mutex_t));
		checkpointer((void *)bloom_bPx2nd_mutex,__FILE__,"calloc","bloom_bPx2nd_mutex" ,__LINE__ -1 );
		bloom_bPx2nd = (struct bloom*)calloc(256,sizeof(struct bloom));
		checkpointer((void *)bloom_bPx2nd,__FILE__,"calloc","bloom_bPx2nd" ,__LINE__ -1 );
		bloom_bPx2nd_checksums = (struct checksumsha256*) calloc(256,sizeof(struct checksumsha256));
		checkpointer((void *)bloom_bPx2nd_checksums,__FILE__,"calloc","bloom_bPx2nd_checksums" ,__LINE__ -1 );
		bloom_bP2_totalbytes = 0;
		for(i=0; i< 256; i++)	{
			pthread_mutex_init(&bloom_bPx2nd_mutex[i],NULL);
			if(bloom_init2(&bloom_bPx2nd[i],itemsbloom2,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init _ %i\n",i);
				exit(0);
			}
			bloom_bP2_totalbytes += bloom_bPx2nd[i].bytes;
		}
		printf(": %.2f MB\n",(float)((float)(uint64_t)bloom_bP2_totalbytes/(float)(uint64_t)1048576));
		

		bloom_bPx3rd_mutex = (pthread_mutex_t*) calloc(256,sizeof(pthread_mutex_t));
		checkpointer((void *)bloom_bPx3rd_mutex,__FILE__,"calloc","bloom_bPx3rd_mutex" ,__LINE__ -1 );
		bloom_bPx3rd = (struct bloom*)calloc(256,sizeof(struct bloom));
		checkpointer((void *)bloom_bPx3rd,__FILE__,"calloc","bloom_bPx3rd" ,__LINE__ -1 );
		bloom_bPx3rd_checksums = (struct checksumsha256*) calloc(256,sizeof(struct checksumsha256));
		checkpointer((void *)bloom_bPx3rd_checksums,__FILE__,"calloc","bloom_bPx3rd_checksums" ,__LINE__ -1 );
		
		printf("[+] Bloom filter for %" PRIu64 " elements ",bsgs_m3);
		bloom_bP3_totalbytes = 0;
		for(i=0; i< 256; i++)	{
			pthread_mutex_init(&bloom_bPx3rd_mutex[i],NULL);
			if(bloom_init2(&bloom_bPx3rd[i],itemsbloom3,0.000001)	== 1){
				fprintf(stderr,"[E] error bloom_init %i\n",i);
				exit(0);
			}
			bloom_bP3_totalbytes += bloom_bPx3rd[i].bytes;
		}
		printf(": %.2f MB\n",(float)((float)(uint64_t)bloom_bP3_totalbytes/(float)(uint64_t)1048576));





		BSGS_MP = secp->ComputePublicKey(&BSGS_M);
		BSGS_MP_double = secp->ComputePublicKey(&BSGS_M_double);
		BSGS_MP2 = secp->ComputePublicKey(&BSGS_M2);
		BSGS_MP2_double = secp->ComputePublicKey(&BSGS_M2_double);
		BSGS_MP3 = secp->ComputePublicKey(&BSGS_M3);
		BSGS_MP3_double = secp->ComputePublicKey(&BSGS_M3_double);
		
		BSGS_AMP2.reserve(32);
		BSGS_AMP3.reserve(32);
		
		GSn.reserve(CPU_GRP_SIZE/2);

		i= 0;


		/* New aMP table just to keep the same code of JLP */
		/* Auxiliar Points to speed up calculations for the main bloom filter check */
		
		Point bsP = secp->Negation(BSGS_MP_double);
		Point g = bsP;
		GSn[0] = g;
		

		g = secp->DoubleDirect(g);
		GSn[1] = g;
		
		
		for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
			g = secp->AddDirect(g,bsP);
			GSn[i] = g;
		}
		
		/* For next center point */
		_2GSn = secp->DoubleDirect(GSn[CPU_GRP_SIZE / 2 - 1]);
		
		
		i = 0;
		point_temp.Set(BSGS_MP2);
		BSGS_AMP2[0] = secp->Negation(point_temp);
		BSGS_AMP2[0].Reduce();
		point_temp.Set(BSGS_MP2_double);
		point_temp = secp->Negation(point_temp);
		
		
		for(i = 1; i < 32; i++)	{
			BSGS_AMP2[i] = secp->AddDirect(BSGS_AMP2[i-1],point_temp);
			BSGS_AMP2[i].Reduce();
		}
		
		i  = 0;
		point_temp.Set(BSGS_MP3);
		BSGS_AMP3[0] = secp->Negation(point_temp);
		BSGS_AMP3[0].Reduce();
		point_temp.Set(BSGS_MP3_double);
		point_temp = secp->Negation(point_temp);

		for(i = 1; i < 32; i++)	{
			BSGS_AMP3[i] = secp->AddDirect(BSGS_AMP3[i-1],point_temp);
			BSGS_AMP3[i].Reduce();
		}

		bytes = (uint64_t)bsgs_m3 * (uint64_t) sizeof(struct bsgs_xvalue);
		printf("[+] Allocating %.2f MB for %" PRIu64  " bP Points\n",(double)(bytes/1048576),bsgs_m3);
		
		bPtable = (struct bsgs_xvalue*) malloc(bytes);
		checkpointer((void *)bPtable,__FILE__,"malloc","bPtable" ,__LINE__ -1 );
		memset(bPtable,0,bytes);
		
		if(FLAGSAVEREADFILE)	{
			/*Reading file for 1st bloom filter */

			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_4_%" PRIu64 ".blm",bsgs_m);
			fd_aux1 = fopen(buffer_bloom_file,"rb");
			if(fd_aux1 != NULL)	{
				printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
				fflush(stdout);
				for(i = 0; i < 256;i++)	{
					bf_ptr = (char*) bloom_bP[i].bf;	/*We need to save the current bf pointer*/
					readed = fread(&bloom_bP[i],sizeof(struct bloom),1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(0);
					}
					bloom_bP[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
					readed = fread(bloom_bP[i].bf,bloom_bP[i].bytes,1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(0);
					}
					readed = fread(&bloom_bP_checksums[i],sizeof(struct checksumsha256),1,fd_aux1);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(0);
					}
					memset(rawvalue,0,32);
					if(FLAGSKIPCHECKSUM == 0)	{
						sha256((uint8_t*)bloom_bP[i].bf,bloom_bP[i].bytes,(uint8_t*)rawvalue);
						if(memcmp(bloom_bP_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bP_checksums[i].backup,rawvalue,32) != 0 )	{	/* Verification */
							fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
							exit(0);
						}
					}
					if(i % 64 == 0 )	{
						printf(".");
						fflush(stdout);
					}
				}
				printf(" Done!\n");
				fclose(fd_aux1);
				memset(buffer_bloom_file,0,1024);
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_3_%" PRIu64 ".blm",bsgs_m);
				fd_aux1 = fopen(buffer_bloom_file,"rb");
				if(fd_aux1 != NULL)	{
					printf("[W] Unused file detected %s you can delete it without worry\n",buffer_bloom_file);
					fclose(fd_aux1);
				}
				FLAGREADEDFILE1 = 1;
			}
			else	{	/*Checking for old file    keyhunt_bsgs_3_   */
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_3_%" PRIu64 ".blm",bsgs_m);
				fd_aux1 = fopen(buffer_bloom_file,"rb");
				if(fd_aux1 != NULL)	{
					printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						bf_ptr = (char*) bloom_bP[i].bf;	/*We need to save the current bf pointer*/
						readed = fread(&oldbloom_bP,sizeof(struct oldbloom),1,fd_aux1);
						
						
						if(readed != 1)	{
							fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
							exit(0);
						}
						memcpy(&bloom_bP[i],&oldbloom_bP,sizeof(struct bloom));//We only need to copy the part data to the new bloom size, not from the old size
						bloom_bP[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
						
						readed = fread(bloom_bP[i].bf,bloom_bP[i].bytes,1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
							exit(0);
						}
						memcpy(bloom_bP_checksums[i].data,oldbloom_bP.checksum,32);
						memcpy(bloom_bP_checksums[i].backup,oldbloom_bP.checksum_backup,32);
						memset(rawvalue,0,32);
						if(FLAGSKIPCHECKSUM == 0)	{
							sha256((uint8_t*)bloom_bP[i].bf,bloom_bP[i].bytes,(uint8_t*)rawvalue);
							if(memcmp(bloom_bP_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bP_checksums[i].backup,rawvalue,32) != 0 )	{	/* Verification */
								fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
								exit(0);
							}
						}
						if(i % 32 == 0 )	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux1);
					FLAGUPDATEFILE1 = 1;	/* Flag to migrate the data to the new File keyhunt_bsgs_4_ */
					FLAGREADEDFILE1 = 1;
					
				}
				else	{
					FLAGREADEDFILE1 = 0;
					//Flag to make the new file
				}
			}
			
			/*Reading file for 2nd bloom filter */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_6_%" PRIu64 ".blm",bsgs_m2);
			fd_aux2 = fopen(buffer_bloom_file,"rb");
			if(fd_aux2 != NULL)	{
				printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
				fflush(stdout);
				for(i = 0; i < 256;i++)	{
					bf_ptr = (char*) bloom_bPx2nd[i].bf;	/*We need to save the current bf pointer*/
					readed = fread(&bloom_bPx2nd[i],sizeof(struct bloom),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(0);
					}
					bloom_bPx2nd[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
					readed = fread(bloom_bPx2nd[i].bf,bloom_bPx2nd[i].bytes,1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(0);
					}
					readed = fread(&bloom_bPx2nd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(0);
					}
					memset(rawvalue,0,32);
					if(FLAGSKIPCHECKSUM == 0)	{
						sha256((uint8_t*)bloom_bPx2nd[i].bf,bloom_bPx2nd[i].bytes,(uint8_t*)rawvalue);
						if(memcmp(bloom_bPx2nd_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bPx2nd_checksums[i].backup,rawvalue,32) != 0 )	{		/* Verification */
							fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
							exit(0);
						}
					}
					if(i % 64 == 0)	{
						printf(".");
						fflush(stdout);
					}
				}
				fclose(fd_aux2);
				printf(" Done!\n");
				memset(buffer_bloom_file,0,1024);
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_5_%" PRIu64 ".blm",bsgs_m2);
				fd_aux2 = fopen(buffer_bloom_file,"rb");
				if(fd_aux2 != NULL)	{
					printf("[W] Unused file detected %s you can delete it without worry\n",buffer_bloom_file);
					fclose(fd_aux2);
				}
				memset(buffer_bloom_file,0,1024);
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_1_%" PRIu64 ".blm",bsgs_m2);
				fd_aux2 = fopen(buffer_bloom_file,"rb");
				if(fd_aux2 != NULL)	{
					printf("[W] Unused file detected %s you can delete it without worry\n",buffer_bloom_file);
					fclose(fd_aux2);
				}
				FLAGREADEDFILE2 = 1;
			}
			else	{	
				FLAGREADEDFILE2 = 0;
			}
			
			/*Reading file for bPtable */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_2_%" PRIu64 ".tbl",bsgs_m3);
			fd_aux3 = fopen(buffer_bloom_file,"rb");
			if(fd_aux3 != NULL)	{
				printf("[+] Reading bP Table from file %s .",buffer_bloom_file);
				fflush(stdout);
				rsize = fread(bPtable,bytes,1,fd_aux3);
				if(rsize != 1)	{
					fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
					exit(0);
				}
				rsize = fread(checksum,32,1,fd_aux3);
				if(FLAGSKIPCHECKSUM == 0)	{
					sha256((uint8_t*)bPtable,bytes,(uint8_t*)checksum_backup);
					if(memcmp(checksum,checksum_backup,32) != 0)	{
						fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
						exit(0);
					}
				}
				printf("... Done!\n");
				fclose(fd_aux3);
				FLAGREADEDFILE3 = 1;
			}
			else	{
				FLAGREADEDFILE3 = 0;
			}
			
			/*Reading file for 3rd bloom filter */
			snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_7_%" PRIu64 ".blm",bsgs_m3);
			fd_aux2 = fopen(buffer_bloom_file,"rb");
			if(fd_aux2 != NULL)	{
				printf("[+] Reading bloom filter from file %s ",buffer_bloom_file);
				fflush(stdout);
				for(i = 0; i < 256;i++)	{
					bf_ptr = (char*) bloom_bPx3rd[i].bf;	/*We need to save the current bf pointer*/
					readed = fread(&bloom_bPx3rd[i],sizeof(struct bloom),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(0);
					}
					bloom_bPx3rd[i].bf = (uint8_t*)bf_ptr;	/* Restoring the bf pointer*/
					readed = fread(bloom_bPx3rd[i].bf,bloom_bPx3rd[i].bytes,1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(0);
					}
					readed = fread(&bloom_bPx3rd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
					if(readed != 1)	{
						fprintf(stderr,"[E] Error reading the file %s\n",buffer_bloom_file);
						exit(0);
					}
					memset(rawvalue,0,32);
					if(FLAGSKIPCHECKSUM == 0)	{
						sha256((uint8_t*)bloom_bPx3rd[i].bf,bloom_bPx3rd[i].bytes,(uint8_t*)rawvalue);
						if(memcmp(bloom_bPx3rd_checksums[i].data,rawvalue,32) != 0 || memcmp(bloom_bPx3rd_checksums[i].backup,rawvalue,32) != 0 )	{		/* Verification */
							fprintf(stderr,"[E] Error checksum file mismatch! %s\n",buffer_bloom_file);
							exit(0);
						}
					}
					if(i % 64 == 0)	{
						printf(".");
						fflush(stdout);
					}
				}
				fclose(fd_aux2);
				printf(" Done!\n");
				FLAGREADEDFILE4 = 1;
			}
			else	{
				FLAGREADEDFILE4 = 0;
			}
			
		}
		
		if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE3 || !FLAGREADEDFILE4)	{
			if(FLAGREADEDFILE1 == 1)	{
				/* 
					We need just to make File 2 to File 4 this is
					- Second bloom filter 5%
					- third  bloom fitler 0.25 %
					- bp Table 0.25 %
				*/
				printf("[I] We need to recalculate some files, don't worry this is only 3%% of the previous work\n");
				FINISHED_THREADS_COUNTER = 0;
				FINISHED_THREADS_BP = 0;
				FINISHED_ITEMS = 0;
				salir = 0;
				BASE = 0;
				THREADCOUNTER = 0;
				if(THREADBPWORKLOAD >= bsgs_m2)	{
					THREADBPWORKLOAD = bsgs_m2;
				}
				THREADCYCLES = bsgs_m2 / THREADBPWORKLOAD;
				PERTHREAD_R = bsgs_m2 % THREADBPWORKLOAD;
				if(PERTHREAD_R != 0)	{
					THREADCYCLES++;
				}
				
				printf("\r[+] processing %lu/%lu bP points : %i%%\r",FINISHED_ITEMS,bsgs_m,(int) (((double)FINISHED_ITEMS/(double)bsgs_m)*100));
				fflush(stdout);
				
				tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
				bPload_mutex = (pthread_mutex_t*) calloc(NTHREADS,sizeof(pthread_mutex_t));
				checkpointer((void *)bPload_mutex,__FILE__,"calloc","bPload_mutex" ,__LINE__ -1 );
				bPload_temp_ptr = (struct bPload*) calloc(NTHREADS,sizeof(struct bPload));
				checkpointer((void *)bPload_temp_ptr,__FILE__,"calloc","bPload_temp_ptr" ,__LINE__ -1 );
				bPload_threads_available = (char*) calloc(NTHREADS,sizeof(char));
				checkpointer((void *)bPload_threads_available,__FILE__,"calloc","bPload_threads_available" ,__LINE__ -1 );
				
				memset(bPload_threads_available,1,NTHREADS);
				
				for(i = 0; i < NTHREADS; i++)	{
					pthread_mutex_init(&bPload_mutex[i],NULL);
				}
				
				do	{
					for(i = 0; i < NTHREADS && !salir; i++)	{

						if(bPload_threads_available[i] && !salir)	{
							bPload_threads_available[i] = 0;
							bPload_temp_ptr[i].from = BASE;
							bPload_temp_ptr[i].threadid = i;
							bPload_temp_ptr[i].finished = 0;
							if( THREADCOUNTER < THREADCYCLES-1)	{
								bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD;
								bPload_temp_ptr[i].workload = THREADBPWORKLOAD;
							}
							else	{
								bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
								bPload_temp_ptr[i].workload = THREADBPWORKLOAD + PERTHREAD_R;
								salir = 1;
							}
							s = pthread_create(&tid[i],NULL,thread_bPload_2blooms,(void*) &bPload_temp_ptr[i]);
							if(s != 0){
								printf("Thread creation failed. Error code: %d\n", s);
								exit(EXIT_FAILURE);
							}
							pthread_detach(tid[i]);
							BASE+=THREADBPWORKLOAD;
							THREADCOUNTER++;
						}
					}

					if(OLDFINISHED_ITEMS != FINISHED_ITEMS)	{
						printf("\r[+] processing %lu/%lu bP points : %i%%\r",FINISHED_ITEMS,bsgs_m2,(int) (((double)FINISHED_ITEMS/(double)bsgs_m2)*100));
						fflush(stdout);
						OLDFINISHED_ITEMS = FINISHED_ITEMS;
					}
					
					for(i = 0 ; i < NTHREADS ; i++)	{

						pthread_mutex_lock(&bPload_mutex[i]);
						finished = bPload_temp_ptr[i].finished;
						pthread_mutex_unlock(&bPload_mutex[i]);
						if(finished)	{
							bPload_temp_ptr[i].finished = 0;
							bPload_threads_available[i] = 1;
							FINISHED_ITEMS += bPload_temp_ptr[i].workload;
							FINISHED_THREADS_COUNTER++;
						}
					}
					
				}while(FINISHED_THREADS_COUNTER < THREADCYCLES);
				printf("\r[+] processing %lu/%lu bP points : 100%%     \n",bsgs_m2,bsgs_m2);
				
				free(tid);
				free(bPload_mutex);
				free(bPload_temp_ptr);
				free(bPload_threads_available);
			}
			else{	
				/* We need just to do all the files 
					- first  bllom filter 100% 
					- Second bloom filter 5%
					- third  bloom fitler 0.25 %
					- bp Table 0.25 %
				*/
				FINISHED_THREADS_COUNTER = 0;
				FINISHED_THREADS_BP = 0;
				FINISHED_ITEMS = 0;
				salir = 0;
				BASE = 0;
				THREADCOUNTER = 0;
				if(THREADBPWORKLOAD >= bsgs_m)	{
					THREADBPWORKLOAD = bsgs_m;
				}
				THREADCYCLES = bsgs_m / THREADBPWORKLOAD;
				PERTHREAD_R = bsgs_m % THREADBPWORKLOAD;
				if(PERTHREAD_R != 0)	{
					THREADCYCLES++;
				}
				
				printf("\r[+] processing %lu/%lu bP points : %i%%\r",FINISHED_ITEMS,bsgs_m,(int) (((double)FINISHED_ITEMS/(double)bsgs_m)*100));
				fflush(stdout);
				
				tid = (pthread_t *) calloc(NTHREADS,sizeof(pthread_t));
				bPload_mutex = (pthread_mutex_t*) calloc(NTHREADS,sizeof(pthread_mutex_t));
				checkpointer((void *)tid,__FILE__,"calloc","tid" ,__LINE__ -1 );
				checkpointer((void *)bPload_mutex,__FILE__,"calloc","bPload_mutex" ,__LINE__ -1 );
				
				bPload_temp_ptr = (struct bPload*) calloc(NTHREADS,sizeof(struct bPload));
				checkpointer((void *)bPload_temp_ptr,__FILE__,"calloc","bPload_temp_ptr" ,__LINE__ -1 );
				bPload_threads_available = (char*) calloc(NTHREADS,sizeof(char));
				checkpointer((void *)bPload_threads_available,__FILE__,"calloc","bPload_threads_available" ,__LINE__ -1 );
				

				memset(bPload_threads_available,1,NTHREADS);
				
				for(i = 0; i < NTHREADS; i++)	{
					pthread_mutex_init(&bPload_mutex[i],NULL);
				}
				
				do	{
					for(i = 0; i < NTHREADS && !salir; i++)	{

						if(bPload_threads_available[i] && !salir)	{
							bPload_threads_available[i] = 0;
							bPload_temp_ptr[i].from = BASE;
							bPload_temp_ptr[i].threadid = i;
							bPload_temp_ptr[i].finished = 0;
							if( THREADCOUNTER < THREADCYCLES-1)	{
								bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD;
								bPload_temp_ptr[i].workload = THREADBPWORKLOAD;
							}
							else	{
								bPload_temp_ptr[i].to = BASE + THREADBPWORKLOAD + PERTHREAD_R;
								bPload_temp_ptr[i].workload = THREADBPWORKLOAD + PERTHREAD_R;
								salir = 1;
							}

							s = pthread_create(&tid[i],NULL,thread_bPload,(void*) &bPload_temp_ptr[i]);
							if(s != 0){
								printf("Thread creation failed. Error code: %d\n", s);
								exit(EXIT_FAILURE);
							}
							pthread_detach(tid[i]);
							BASE+=THREADBPWORKLOAD;
							THREADCOUNTER++;
						}
					}
					if(OLDFINISHED_ITEMS != FINISHED_ITEMS)	{
						printf("\r[+] processing %lu/%lu bP points : %i%%\r",FINISHED_ITEMS,bsgs_m,(int) (((double)FINISHED_ITEMS/(double)bsgs_m)*100));
						fflush(stdout);
						OLDFINISHED_ITEMS = FINISHED_ITEMS;
					}
					
					for(i = 0 ; i < NTHREADS ; i++)	{

						pthread_mutex_lock(&bPload_mutex[i]);
						finished = bPload_temp_ptr[i].finished;
						pthread_mutex_unlock(&bPload_mutex[i]);
						if(finished)	{
							bPload_temp_ptr[i].finished = 0;
							bPload_threads_available[i] = 1;
							FINISHED_ITEMS += bPload_temp_ptr[i].workload;
							FINISHED_THREADS_COUNTER++;
						}
					}
					
				}while(FINISHED_THREADS_COUNTER < THREADCYCLES);
				printf("\r[+] processing %lu/%lu bP points : 100%%     \n",bsgs_m,bsgs_m);
				
				free(tid);
				free(bPload_mutex);
				free(bPload_temp_ptr);
				free(bPload_threads_available);
			}
		}
		
		if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE4)	{
			printf("[+] Making checkums .. ");
			fflush(stdout);
		}	
		if(!FLAGREADEDFILE1)	{
			for(i = 0; i < 256 ; i++)	{
				sha256((uint8_t*)bloom_bP[i].bf, bloom_bP[i].bytes,(uint8_t*) bloom_bP_checksums[i].data);
				memcpy(bloom_bP_checksums[i].backup,bloom_bP_checksums[i].data,32);
			}
			printf(".");
		}
		if(!FLAGREADEDFILE2)	{
			for(i = 0; i < 256 ; i++)	{
				sha256((uint8_t*)bloom_bPx2nd[i].bf, bloom_bPx2nd[i].bytes,(uint8_t*) bloom_bPx2nd_checksums[i].data);
				memcpy(bloom_bPx2nd_checksums[i].backup,bloom_bPx2nd_checksums[i].data,32);
			}
			printf(".");
		}
		if(!FLAGREADEDFILE4)	{
			for(i = 0; i < 256 ; i++)	{
				sha256((uint8_t*)bloom_bPx3rd[i].bf, bloom_bPx3rd[i].bytes,(uint8_t*) bloom_bPx3rd_checksums[i].data);
				memcpy(bloom_bPx3rd_checksums[i].backup,bloom_bPx3rd_checksums[i].data,32);
			}
			printf(".");
		}
		if(!FLAGREADEDFILE1 || !FLAGREADEDFILE2 || !FLAGREADEDFILE4)	{
			printf(" done\n");
			fflush(stdout);
		}	
		if(!FLAGREADEDFILE3)	{
			printf("[+] Sorting %lu elements... ",bsgs_m3);
			fflush(stdout);
			bsgs_sort(bPtable,bsgs_m3);
			sha256((uint8_t*)bPtable, bytes,(uint8_t*) checksum);
			memcpy(checksum_backup,checksum,32);
			printf("Done!\n");
			fflush(stdout);
		}
		if(FLAGSAVEREADFILE || FLAGUPDATEFILE1 )	{
			if(!FLAGREADEDFILE1 || FLAGUPDATEFILE1)	{
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_4_%" PRIu64 ".blm",bsgs_m);
				
				if(FLAGUPDATEFILE1)	{
					printf("[W] Updating old file into a new one\n");
				}
				
				/* Writing file for 1st bloom filter */
				
				fd_aux1 = fopen(buffer_bloom_file,"wb");
				if(fd_aux1 != NULL)	{
					printf("[+] Writing bloom filter to file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						readed = fwrite(&bloom_bP[i],sizeof(struct bloom),1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(0);
						}
						readed = fwrite(bloom_bP[i].bf,bloom_bP[i].bytes,1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(0);
						}
						readed = fwrite(&bloom_bP_checksums[i],sizeof(struct checksumsha256),1,fd_aux1);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(0);
						}
						if(i % 64 == 0)	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux1);
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(0);
				}
			}
			if(!FLAGREADEDFILE2  )	{
				
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_6_%" PRIu64 ".blm",bsgs_m2);
								
				/* Writing file for 2nd bloom filter */
				fd_aux2 = fopen(buffer_bloom_file,"wb");
				if(fd_aux2 != NULL)	{
					printf("[+] Writing bloom filter to file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						readed = fwrite(&bloom_bPx2nd[i],sizeof(struct bloom),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(0);
						}
						readed = fwrite(bloom_bPx2nd[i].bf,bloom_bPx2nd[i].bytes,1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(0);
						}
						readed = fwrite(&bloom_bPx2nd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(0);
						}
						if(i % 64 == 0)	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux2);	
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(0);
				}
			}
			
			if(!FLAGREADEDFILE3)	{
				/* Writing file for bPtable */
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_2_%" PRIu64 ".tbl",bsgs_m3);
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
					exit(0);
				}
			}
			if(!FLAGREADEDFILE4)	{
				snprintf(buffer_bloom_file,1024,"keyhunt_bsgs_7_%" PRIu64 ".blm",bsgs_m3);
								
				/* Writing file for 3rd bloom filter */
				fd_aux2 = fopen(buffer_bloom_file,"wb");
				if(fd_aux2 != NULL)	{
					printf("[+] Writing bloom filter to file %s ",buffer_bloom_file);
					fflush(stdout);
					for(i = 0; i < 256;i++)	{
						readed = fwrite(&bloom_bPx3rd[i],sizeof(struct bloom),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(0);
						}
						readed = fwrite(bloom_bPx3rd[i].bf,bloom_bPx3rd[i].bytes,1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s\n",buffer_bloom_file);
							exit(0);
						}
						readed = fwrite(&bloom_bPx3rd_checksums[i],sizeof(struct checksumsha256),1,fd_aux2);
						if(readed != 1)	{
							fprintf(stderr,"[E] Error writing the file %s please delete it\n",buffer_bloom_file);
							exit(0);
						}
						if(i % 64 == 0)	{
							printf(".");
							fflush(stdout);
						}
					}
					printf(" Done!\n");
					fclose(fd_aux2);
				}
				else	{
					fprintf(stderr,"[E] Error can't create the file %s\n",buffer_bloom_file);
					exit(0);
				}
			}
		}
	}
	/* 
		Here we already finish the BSGS setup
		- Baby table and bloom filters are alrady setup
	
	*/
	
	
    int server_fd, client_fd;
    struct sockaddr_in address;
	char clientIP[INET_ADDRSTRLEN];
	int clientPort,addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Setting socket options
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Setting address parameters
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(IP);
    address.sin_port = htons(PORT);
    // Binding socket to address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
	printf("[+] Listening in %s:%i\n",IP,port);
    // Listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

	pthread_t tid;
	while(1) {
		// Accepting incoming connection
		if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
			perror("accept failed");
			exit(EXIT_FAILURE);
		}
		inet_ntop(AF_INET, &(address.sin_addr), clientIP, INET_ADDRSTRLEN);
		clientPort = ntohs(address.sin_port);
		
		printf("[+] Accepting incoming conection from %s:%i\n",clientIP,clientPort);
		fflush(stdout);
		// Creating new thread to handle client
		if (pthread_create(&tid, NULL, client_handler, &client_fd) != 0) {
			perror("pthread_create failed");
			printf("Failed to attend to one client\n");
		}
		else	{
			if (pthread_join(tid, NULL) != 0) {
				fprintf(stderr, "Failed to join thread.\n");
				exit(EXIT_FAILURE);
			}
		}
		printf("[+] Closing conection from %s:%i\n",clientIP,clientPort);
		fflush(stdout);
	}
	
	close(server_fd);
}

void pubkeytopubaddress_dst(char *pkey,int length,char *dst)	{
	char digest[60];
	size_t pubaddress_size = 40;
	sha256((uint8_t*)pkey, length,(uint8_t*) digest);
	RMD160Data((const unsigned char*)digest,32, digest+1);
	digest[0] = 0;
	sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
	sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);
	if(!b58enc(dst,&pubaddress_size,digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}

void rmd160toaddress_dst(char *rmd,char *dst){
	char digest[60];
	size_t pubaddress_size = 40;
	digest[0] = byte_encode_crypto;
	memcpy(digest+1,rmd,20);
	sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
	sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);
	if(!b58enc(dst,&pubaddress_size,digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
}


char *pubkeytopubaddress(char *pkey,int length)	{
	char *pubaddress = (char*) calloc(MAXLENGTHADDRESS+10,1);
	char *digest = (char*) calloc(60,1);
	size_t pubaddress_size = MAXLENGTHADDRESS+10;
	checkpointer((void *)pubaddress,__FILE__,"malloc","pubaddress" ,__LINE__ -1 );
	checkpointer((void *)digest,__FILE__,"malloc","digest" ,__LINE__ -1 );
	//digest [000...0]
 	sha256((uint8_t*)pkey, length,(uint8_t*) digest);
	//digest [SHA256 32 bytes+000....0]
	RMD160Data((const unsigned char*)digest,32, digest+1);
	//digest [? +RMD160 20 bytes+????000....0]
	digest[0] = 0;
	//digest [0 +RMD160 20 bytes+????000....0]
	sha256((uint8_t*)digest, 21,(uint8_t*) digest+21);
	//digest [0 +RMD160 20 bytes+SHA256 32 bytes+....0]
	sha256((uint8_t*)digest+21, 32,(uint8_t*) digest+21);
	//digest [0 +RMD160 20 bytes+SHA256 32 bytes+....0]
	if(!b58enc(pubaddress,&pubaddress_size,digest,25)){
		fprintf(stderr,"error b58enc\n");
	}
	free(digest);
	return pubaddress;	// pubaddress need to be free by te caller funtion
}

void publickeytohashrmd160_dst(char *pkey,int length,char *dst)	{
	char digest[32];
	//digest [000...0]
 	sha256((uint8_t*)pkey, length,(uint8_t*) digest);
	//digest [SHA256 32 bytes]
	RMD160Data((const unsigned char*)digest,32, dst);
	//hash160 [RMD160 20 bytes]
}

char *publickeytohashrmd160(char *pkey,int length)	{
	char *hash160 = (char*) malloc(20);
	char *digest = (char*) malloc(32);
	checkpointer((void *)hash160,__FILE__,"malloc","hash160" ,__LINE__ -1 );
	checkpointer((void *)digest,__FILE__,"malloc","digest" ,__LINE__ -1 );
	//digest [000...0]
 	sha256((uint8_t*)pkey, length,(uint8_t*) digest);
	//digest [SHA256 32 bytes]
	RMD160Data((const unsigned char*)digest,32, hash160);
	//hash160 [RMD160 20 bytes]
	free(digest);
	return hash160;	// hash160 need to be free by te caller funtion
}


/*	OK	*/
void bsgs_swap(struct bsgs_xvalue *a,struct bsgs_xvalue *b)	{
	struct bsgs_xvalue t;
	t	= *a;
	*a =  *b;
	*b =   t;
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

int bsgs_searchbinary(struct bsgs_xvalue *buffer,char *data,int64_t array_length,uint64_t *r_value) {
	int64_t min,max,half,current;
	int r = 0,rcmp;
	min = 0;
	current = 0;
	max = array_length;
	half = array_length;
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
	char xpoint_raw[32],*aux_c,*hextemp;
	Int base_key,keyfound;
	Point base_point,point_aux,point_found;
	uint32_t r, cycles;
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
	

	
	cycles = bsgs_aux / 1024;
	if(bsgs_aux % 1024 != 0)	{
		cycles++;
	}

	
	intaux.Set(&BSGS_M_double);
	intaux.Mult(CPU_GRP_SIZE/2);
	intaux.Add(&BSGS_M);
	
	/*
		intaux hold the Current middle range value (Current)
		(BSGS_M*2) * (CPU_GRP_SIZE/2) + BSGS_M
		or
		(BSGS_M * 512)  + BSGS_M
	*/
	/*
		while base_key is less than n_range_end then:
	*/
	do	{
		
	/*
		We do this in an atomic pthread_mutex operation to not affect others threads
		so BSGS_CURRENT is never the same between threads
	*/
		pthread_mutex_lock(&mutex_bsgs_thread);

		base_key.Set(&BSGS_CURRENT);	/* we need to set our base_key to the current BSGS_CURRENT value*/
		BSGS_CURRENT.Add(&BSGS_N);		/*Then add BSGS_N to BSGS_CURRENT*/
		BSGS_CURRENT.Add(&BSGS_N);		/*Then add BSGS_N to BSGS_CURRENT*/
		
		pthread_mutex_unlock(&mutex_bsgs_thread);

		if(base_key.IsGreaterOrEqual(&n_range_end))
			break;


		//base point is the point of the current start range (Base_key)
		base_point = secp->ComputePublicKey(&base_key);

		km.Set(&base_key);
		km.Neg();
		 
		km.Add(&secp->order);
		km.Sub(&intaux);

		//point_aux =-( basekey + ((BSGS_M*2) * 512)  + BSGS_M)
		point_aux = secp->ComputePublicKey(&km);
		
		

		if(base_point.equals(OriginalPointsBSGS))	{
			hextemp = base_key.GetBase16();
			printf("[+] Thread Key found privkey %s  \n",hextemp);
			aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed,base_point);
			printf("[+] Publickey %s\n",aux_c);
			
			pthread_mutex_lock(&write_keys);

			filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
			if(filekey != NULL)	{
				fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
				fclose(filekey);
			}
			BSGSkeyfound.Set(&base_key);
			pthread_mutex_unlock(&write_keys);

			free(hextemp);
			free(aux_c);
			
			bsgs_found = 1;
		}
		else	{

			startP  = secp->AddDirect(OriginalPointsBSGS,point_aux);
			
			uint32_t j = 0;
			while( j < cycles && bsgs_found == 0 )	{
			
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
					
#if 0 /* For this BSGS we don't neet to calculate the Y value of intermediate points */
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

#if 0	/* For this BSGS we don't neet to calculate the Y value of intermediate points */
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


#if 0 /* For this BSGS we don't neet to calculate the Y value of intermediate points */
pn.y.ModSub(&GSn[i].x,&pn.x);
pn.y.ModMulK1(&_s);
pn.y.ModAdd(&GSn[i].y);
#endif

				pts[0] = pn;
				
				for(int i = 0; i<CPU_GRP_SIZE && bsgs_found == 0; i++) {
					
					pts[i].x.Get32Bytes((unsigned char*)xpoint_raw);
					
					r = bloom_check(&bloom_bP[((unsigned char)xpoint_raw[0])],xpoint_raw,32);
					
					if(r) {
						r = bsgs_secondcheck(&base_key,((j*1024) + i),&keyfound);
						if(r)	{
							hextemp = keyfound.GetBase16();
							printf("[+] Thread Key found privkey %s   \n",hextemp);
							point_found = secp->ComputePublicKey(&keyfound);
							aux_c = secp->GetPublicKeyHex(OriginalPointsBSGScompressed,point_found);
							printf("[+] Publickey %s\n",aux_c);
							pthread_mutex_lock(&write_keys);

							filekey = fopen("KEYFOUNDKEYFOUND.txt","a");
							if(filekey != NULL)	{
								fprintf(filekey,"Key found privkey %s\nPublickey %s\n",hextemp,aux_c);
								fclose(filekey);
							}
							BSGSkeyfound.Set(&keyfound);
							pthread_mutex_unlock(&write_keys);
							free(hextemp);
							free(aux_c);
							bsgs_found = 1;

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
				
				
				/* For this BSGS we only need to calculate the Y value of  the next start point  */

				pp.y.ModSub(&_2GSn.x,&pp.x);
				pp.y.ModMulK1(&_s);
				pp.y.ModSub(&_2GSn.y);
				startP = pp;
				
				j++;
			} //while all the aMP points
		} // end else
	}while(base_key.IsLower(&n_range_end) && bsgs_found == 0);
	delete grp;
	pthread_exit(NULL);
}

/*
	The bsgs_secondcheck function is made to perform a second BSGS search in a Range of less size.
	This funtion is made with the especific purpouse to USE a smaller bPtable in RAM.
*/
int bsgs_secondcheck(Int *start_range,uint32_t a,Int *privatekey)	{
	int i = 0,found = 0,r = 0;
	Int base_key;
	Point base_point,point_aux;
	Point BSGS_Q, BSGS_S,BSGS_Q_AMP;
	char xpoint_raw[32];
	
	base_key.Set(&BSGS_M_double);
	base_key.Mult((uint64_t) a);
	base_key.Add(start_range);

	base_point = secp->ComputePublicKey(&base_key);
	point_aux = secp->Negation(base_point);
	/*
		BSGS_S = Q - base_key
				 Q is the target Key
		base_key is the Start range + a*BSGS_M
	*/
	
	BSGS_S = secp->AddDirect(OriginalPointsBSGS,point_aux);
	BSGS_Q.Set(BSGS_S);
	do {
		BSGS_Q_AMP = secp->AddDirect(BSGS_Q,BSGS_AMP2[i]);
		BSGS_S.Set(BSGS_Q_AMP);
		BSGS_S.x.Get32Bytes((unsigned char *) xpoint_raw);
		
		r = bloom_check(&bloom_bPx2nd[(uint8_t) xpoint_raw[0]],xpoint_raw,32);

		if(r)	{
			found = bsgs_thirdcheck(&base_key,i,privatekey);
		}
		i++;
	}while(i < 32 && !found);
	return found;
}

int bsgs_thirdcheck(Int *start_range,uint32_t a,Int *privatekey)	{
	uint64_t j = 0;
	int i = 0,found = 0,r = 0;
	Int base_key,calculatedkey;
	Point base_point,point_aux;
	Point BSGS_Q, BSGS_S,BSGS_Q_AMP;
	char xpoint_raw[32];

	base_key.SetInt32(a);
	base_key.Mult(&BSGS_M2_double);
	base_key.Add(start_range);

	base_point = secp->ComputePublicKey(&base_key);
	point_aux = secp->Negation(base_point);
	
	BSGS_S = secp->AddDirect(OriginalPointsBSGS,point_aux);
	BSGS_Q.Set(BSGS_S);
	
	do {
		BSGS_Q_AMP = secp->AddDirect(BSGS_Q,BSGS_AMP3[i]);
		BSGS_S.Set(BSGS_Q_AMP);
		BSGS_S.x.Get32Bytes((unsigned char *)xpoint_raw);
		r = bloom_check(&bloom_bPx3rd[(uint8_t)xpoint_raw[0]],xpoint_raw,32);
		if(r)	{
			r = bsgs_searchbinary(bPtable,xpoint_raw,bsgs_m3,&j);
			if(r)	{
				calcualteindex(i,&calculatedkey);
				privatekey->Set(&calculatedkey);
				privatekey->Add((uint64_t)(j+1));
				privatekey->Add(&base_key);
				
				point_aux = secp->ComputePublicKey(privatekey);
				
				if(point_aux.x.IsEqual(&OriginalPointsBSGS.x))	{
					found = 1;
				}
				else	{
					calcualteindex(i,&calculatedkey);
					privatekey->Set(&calculatedkey);
					privatekey->Sub((uint64_t)(j+1));
					privatekey->Add(&base_key);
					
					point_aux = secp->ComputePublicKey(privatekey);
					if(point_aux.x.IsEqual(&OriginalPointsBSGS.x))	{
						found = 1;
					}
				}
			}
		}
		else	{
			/*
				For some reason the AddDirect don't return 000000... value when the publickeys are the negated values from each other
				Why JLP?
				This is is an special case
			*/
			if(BSGS_Q.x.IsEqual(&BSGS_AMP3[i].x))	{
				calcualteindex(i,&calculatedkey);
				privatekey->Set(&calculatedkey);
				privatekey->Add(&base_key);
				found = 1;
			}
		}
		i++;
	}while(i < 32 && !found);

	return found;
}

void calcualteindex(int i,Int *key)	{
	if(i == 0)	{
		key->Set(&BSGS_M3);
	}
	else	{
		key->SetInt32(i);
		key->Mult(&BSGS_M3_double);
		key->Add(&BSGS_M3);
	}
}


void sleep_ms(int milliseconds)	{ // cross-platform sleep function
#if defined(_WIN64) && !defined(__CYGWIN__)
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


void *thread_bPload(void *vargp)	{

	char rawvalue[32];
	struct bPload *tt;
	uint64_t i_counter,j,nbStep,to;
	
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];
	Int dy,dyn,_s,_p;
	Point pp,pn;
	
	int i,bloom_bP_index,hLength = (CPU_GRP_SIZE / 2 - 1) ,threadid;
	tt = (struct bPload *)vargp;
	Int km((uint64_t)(tt->from + 1));
	threadid = tt->threadid;

	
	i_counter = tt->from;

	nbStep = (tt->to - tt->from) / CPU_GRP_SIZE;
	
	if( ((tt->to - tt->from) % CPU_GRP_SIZE )  != 0)	{
		nbStep++;
	}
	to = tt->to;
	
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
			bloom_bP_index = (uint8_t)rawvalue[0];

			if(i_counter < bsgs_m3)	{
				if(!FLAGREADEDFILE3)	{
					memcpy(bPtable[i_counter].value,rawvalue+16,BSGS_XVALUE_RAM);
					bPtable[i_counter].index = i_counter;
				}
				if(!FLAGREADEDFILE4)	{
					pthread_mutex_lock(&bloom_bPx3rd_mutex[bloom_bP_index]);
					bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
					pthread_mutex_unlock(&bloom_bPx3rd_mutex[bloom_bP_index]);
				}
			}
			if(i_counter < bsgs_m2 && !FLAGREADEDFILE2)	{
				pthread_mutex_lock(&bloom_bPx2nd_mutex[bloom_bP_index]);
				bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
				pthread_mutex_unlock(&bloom_bPx2nd_mutex[bloom_bP_index]);
			}
			if(i_counter < to && !FLAGREADEDFILE1 )	{
				pthread_mutex_lock(&bloom_bP_mutex[bloom_bP_index]);
				bloom_add(&bloom_bP[bloom_bP_index], rawvalue ,BSGS_BUFFERXPOINTLENGTH);
				pthread_mutex_unlock(&bloom_bP_mutex[bloom_bP_index]);
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
	pthread_mutex_lock(&bPload_mutex[threadid]);
	tt->finished = 1;
	pthread_mutex_unlock(&bPload_mutex[threadid]);
	pthread_exit(NULL);
	return NULL;
}

void *thread_bPload_2blooms(void *vargp)	{
	char rawvalue[32];
	struct bPload *tt;
	uint64_t i_counter,j,nbStep;
	IntGroup *grp = new IntGroup(CPU_GRP_SIZE / 2 + 1);
	Point startP;
	Int dx[CPU_GRP_SIZE / 2 + 1];
	Point pts[CPU_GRP_SIZE];
	Int dy,dyn,_s,_p;
	Point pp,pn;
	int i,bloom_bP_index,hLength = (CPU_GRP_SIZE / 2 - 1) ,threadid;
	tt = (struct bPload *)vargp;
	Int km((uint64_t)(tt->from +1 ));
	threadid = tt->threadid;
	
	i_counter = tt->from;

	nbStep = (tt->to - (tt->from)) / CPU_GRP_SIZE;
	
	if( ((tt->to - (tt->from)) % CPU_GRP_SIZE )  != 0)	{
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
			bloom_bP_index = (uint8_t)rawvalue[0];
			if(i_counter < bsgs_m3)	{
				if(!FLAGREADEDFILE3)	{
					memcpy(bPtable[i_counter].value,rawvalue+16,BSGS_XVALUE_RAM);
					bPtable[i_counter].index = i_counter;
				}
				if(!FLAGREADEDFILE4)	{
					pthread_mutex_lock(&bloom_bPx3rd_mutex[bloom_bP_index]);
					bloom_add(&bloom_bPx3rd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
					pthread_mutex_unlock(&bloom_bPx3rd_mutex[bloom_bP_index]);
				}
			}
			if(i_counter < bsgs_m2 && !FLAGREADEDFILE2)	{
				pthread_mutex_lock(&bloom_bPx2nd_mutex[bloom_bP_index]);
				bloom_add(&bloom_bPx2nd[bloom_bP_index], rawvalue, BSGS_BUFFERXPOINTLENGTH);
				pthread_mutex_unlock(&bloom_bPx2nd_mutex[bloom_bP_index]);
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
	pthread_mutex_lock(&bPload_mutex[threadid]);
	tt->finished = 1;
	pthread_mutex_unlock(&bPload_mutex[threadid]);
	pthread_exit(NULL);
	return NULL;
}


/* This function takes in two parameters:

publickey: a reference to a Point object representing a public key.
dst_address: a pointer to an unsigned char array where the generated binary address will be stored.
The function is designed to generate a binary address for Ethereum using the given public key.
It first extracts the x and y coordinates of the public key as 32-byte arrays, and concatenates them
to form a 64-byte array called bin_publickey. Then, it applies the KECCAK-256 hashing algorithm to
bin_publickey to generate the binary address, which is stored in dst_address. */


void menu() {
	printf("\nUsage:\n");
	printf("-h          show this help\n");
	printf("-k value    Use this only with bsgs mode, k value is factor for M, more speed but more RAM use wisely\n");
	printf("-n number   Check for N sequential numbers before the random chosen, this only works with -R option\n");
	printf("-t tn       Threads number, must be a positive integer\n");
	printf("-p port     TCP port Number for listening conections");
	printf("-i ip		IP Address for listening conections");
	printf("\nExample:\n\n");
	printf("./bsgs -k 512 \n\n");
	exit(EXIT_FAILURE);
}


void checkpointer(void *ptr,const char *file,const char *function,const  char *name,int line)	{
	if(ptr == NULL)	{
		fprintf(stderr,"[E] error in file %s, %s pointer %s on line %i\n",file,function,name,line); 
		exit(EXIT_FAILURE);
	}
}

void writekey(bool compressed,Int *key)	{
	Point publickey;
	FILE *keys;
	char *hextemp,*hexrmd,public_key_hex[132],address[50],rmdhash[20];
	memset(address,0,50);
	memset(public_key_hex,0,132);
	hextemp = key->GetBase16();
	publickey = secp->ComputePublicKey(key);
	secp->GetPublicKeyHex(compressed,publickey,public_key_hex);
	secp->GetHash160(P2PKH,compressed,publickey,(uint8_t*)rmdhash);
	hexrmd = tohex(rmdhash,20);
	rmd160toaddress_dst(rmdhash,address);

	pthread_mutex_lock(&write_keys);
	keys = fopen("KEYFOUNDKEYFOUND.txt","a+");
	if(keys != NULL)	{
		fprintf(keys,"Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);
		fclose(keys);
	}
	printf("\nHit! Private Key: %s\npubkey: %s\nAddress %s\nrmd160 %s\n",hextemp,public_key_hex,address,hexrmd);
	
	pthread_mutex_unlock(&write_keys);
	free(hextemp);
	free(hexrmd);
}


void init_generator()	{
	Point G = secp->ComputePublicKey(&stride);
	Point g;
	g.Set(G);
	Gn.reserve(CPU_GRP_SIZE / 2);
	Gn[0] = g;
	g = secp->DoubleDirect(g);
	Gn[1] = g;
	for(int i = 2; i < CPU_GRP_SIZE / 2; i++) {
		g = secp->AddDirect(g,G);
		Gn[i] = g;
	}
	_2Gn = secp->DoubleDirect(Gn[CPU_GRP_SIZE / 2 - 1]);
}

void* client_handler(void* arg) {
    int client_fd = *(int*)arg;
    char buffer[1024];
	char *hextemp;
	int bytes_received;
	Tokenizer t;
	t.tokens = NULL;
	
	// Peek at the incoming data to determine its length
	bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, MSG_PEEK);
	if (bytes_received <= 0) {
		close(client_fd);
		pthread_exit(NULL);
	}
	
    
	char* newline = (char*) memchr(buffer, '\n', bytes_received);
	size_t line_length = newline ? (newline - buffer) + 1 : bytes_received;
	bytes_received = recv(client_fd, buffer, line_length, 0);
	if (bytes_received <= 0)	{
		close(client_fd);
		pthread_exit(NULL);
	}

	// Process the received bytes here
	buffer[bytes_received] = '\0';
	stringtokenizer(buffer, &t);
	if (t.n != 3) {
		printf("Invalid input format from client, tokens %i : %s\n",t.n, buffer);
		freetokenizer(&t);
		sendstr(client_fd,"400 Bad Request");
		close(client_fd);
		pthread_exit(NULL);
	}

	if(!secp->ParsePublicKeyHex(t.tokens[0],OriginalPointsBSGS,OriginalPointsBSGScompressed))	{
		printf("Invalid publickey format from client %s\n",t.tokens[0]);
		freetokenizer(&t);
		sendstr(client_fd,"400 Bad Request");
		close(client_fd);
		pthread_exit(NULL);		
	}
	if(!(isValidHex(t.tokens[1]) && isValidHex(t.tokens[2])))	{
		printf("Invalid hexadecimal format from client %s:%s\n",t.tokens[1],t.tokens[2]);
		freetokenizer(&t);
		sendstr(client_fd,"400 Bad Request");
		close(client_fd);
		pthread_exit(NULL);	
	}
	
	n_range_start.SetBase16(t.tokens[1]);
	n_range_end.SetBase16(t.tokens[2]);
	
	freetokenizer(&t);
	
	BSGS_CURRENT.Set(&n_range_start);
	
	bool *threads_created;
	pthread_t *threads;
	int *thread_args;
	
	threads_created = (bool*) calloc(NTHREADS,sizeof(bool));
	threads = (pthread_t*) calloc(NTHREADS,sizeof(pthread_t));
	thread_args = (int*) calloc(NTHREADS,sizeof(int));
	checkpointer(threads_created,__FILE__,"calloc","threads_created",__LINE__);
	checkpointer(threads,__FILE__,"calloc","threads",__LINE__);
	checkpointer(thread_args,__FILE__,"calloc","thread_args",__LINE__);

	
	
	int i, rc;

	// Create threads
	for (i = 0; i < NTHREADS; i++) {
		thread_args[i] = i;
		threads_created[i] = true;
		rc = pthread_create(&threads[i], NULL, thread_process_bsgs, &thread_args[i]);
		if (rc != 0) {
			printf("Failed to create thread %d\n", i);
			threads_created[i] = false;
		}

	}

	// Wait for threads to finish
	for (i = 0; i < NTHREADS; i++) {
		if(threads_created[i]){
			rc = pthread_join(threads[i], NULL);
			if (rc != 0) {
				printf("Failed to join thread %d\n", i);
			}
		}
	}
	
	free(threads_created);
	free(threads);
	free(thread_args);
	int message_len;
	if(bsgs_found)	{
		hextemp = BSGSkeyfound.GetBase16();
		message_len = snprintf(buffer, sizeof(buffer), "%s",hextemp);
		free(hextemp);
	}
	else	{
		message_len = snprintf(buffer, sizeof(buffer), "404 Not Found");
	}
	bsgs_found = 0;
	int bytes_sent = send(client_fd, buffer, message_len, 0);
	if (bytes_sent == -1) {
		printf("Failed to send message to client\n");
	}

	
    close(client_fd);
    pthread_exit(NULL);
}

int sendstr(int client_fd,const char *str)	{
	int len = strlen(str);
	int bytes = send(client_fd, str, len, 0);
	if (bytes == -1) {
		printf("Failed to send message to client\n");
	}
	return bytes;
}