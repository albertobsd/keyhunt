/*
Develop by Luis Alberto
email: alberto.bsd@gmail.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "util.h"

int MAXLENGTHADDRESS = 32;

void quicksort(char *arr, int low, int high);
void swap(char *a,char *b);
int partition (char *arr, int low, int high);

int main(int argc,char **argv) {
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
  line_output = malloc(32);
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
          hexs2bin(line_input,line_output);
          fwrite(line_output,1,32,output);
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
  do {
    line_input = malloc(count*32);
  } while(line_input == NULL);
  i = 0;
  while(i < count) {
    fread(line_input+(i*32),1,32,output);
    i++;
  }
  fclose(output);
  output = fopen(argv[2],"wb");
  printf("File %s was create with %u records\n",argv[2],count);
  printf("Sorting once... \n");
  quicksort(line_input,0,count-1);
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
			//printf("quicksort from %i to %i\n",low,high);
      pi = partition(arr, low, high);
      quicksort(arr, low, pi - 1);
      quicksort(arr, pi + 1, high);
  }
}
