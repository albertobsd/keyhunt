/*
Develop by Luis Alberto
email: alberto.bsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "util.h"

int MAXLENGTHADDRESS = 32;

void _sort(char *arr,int n);
void _insertionsort(char *arr, int n);
void _introsort(char *arr,int depthLimit, int n);
void swap(char *a,char *b);
int partition(char *arr, int n);
void heapsort(char  *arr, int n);
void heapify(char *arr, int n, int i);

int main(int argc,char **argv) {
  int readed;
  char *line_input,*line_output,*aux;
  FILE *input,*output;
  int len,diff,i,count = 0;
  if(argc != 3) {
    printf("Usage:\n%s <input hex file> <output binay file>\n",argv[0]);
    exit(0);
  }
  input = fopen(argv[1],"r");
  output = fopen(argv[2],"wb");
  line_input = malloc(1024);
  line_output = malloc(MAXLENGTHADDRESS);
  if(input == NULL || output == NULL ||  line_input== NULL || line_output == NULL ) {
    printf("error fopen or malloc\n");
  }
  while(!feof(input)) {
    aux = fgets(line_input,1024,input);
    if(aux == line_input)  {
      trim(line_input,"\t\n\r ");
      len = strlen(line_input);
      if(len <= 64){
        if(isValidHex(line_input))  {
          if(len < 64) {
            aux = malloc(65);
            diff = 64 - len;
            strcpy(aux+diff,line_input);
            memset(aux,'0',diff);
            memcpy(line_input,aux,65);
            free(aux);
          }
          hexs2bin(line_input,(unsigned char *)line_output);
          fwrite(line_output,1,MAXLENGTHADDRESS,output);
          count++;
        }
        else  {
          printf("Ignoring invalid hexadecimal line: %s\n",line_input);
        }
      }
      else  {
        printf("Ignoring invalid length line: %s\n",line_input);
      }
    }
  }
  fclose(input);
  fclose(output);
  free(line_input);
  output = fopen(argv[2],"rb");
  printf("Allocating memory...\n");
  do {
    line_input = malloc(count*MAXLENGTHADDRESS);
  } while(line_input == NULL);
  i = 0;
  while(i < count) {
    readed = fread(line_input+(i*32),1,MAXLENGTHADDRESS,output);
    if(readed != MAXLENGTHADDRESS)  {
      fprintf(stderr,"error fread()\n");
    }
    i++;
  }
  fclose(output);
  output = fopen(argv[2],"wb");
  printf("File %s was create with %u records\n",argv[2],count);
  printf("Sorting once... ");
  _sort(line_input,count);
  _insertionsort(line_input,count);
  i = 0;
  while(i < count) {
    fwrite(line_input+(i*32),1,32,output);
    i++;
  }
  fclose(output);
  printf("ready\n");
  free(line_output);
  return 0;
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
        heapsort(arr,n);
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
  char *arrj,*temp;
  char key[MAXLENGTHADDRESS];
  int j,i;
  for(i = 1; i < n ; i++ ) {
    j= i-1;
    memcpy(key,arr + (i*MAXLENGTHADDRESS),MAXLENGTHADDRESS);
    arrj = arr + (j*MAXLENGTHADDRESS);
    while(j >= 0 && memcmp(arrj,key,MAXLENGTHADDRESS) > 0) {
      memcpy(arr + ((j+1)*MAXLENGTHADDRESS),arrj,MAXLENGTHADDRESS);
      j--;
      arrj = arr + (j*MAXLENGTHADDRESS);
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

void heapsort(char  *arr, int n)  {
  int i;
  for ( i = n / 2 - 1; i >= 0; i--)
    heapify(arr, n, i);
  for ( i = n - 1; i > 0; i--) {
    swap(arr , arr +(i*MAXLENGTHADDRESS));
    heapify(arr, i, 0);
  }
}
