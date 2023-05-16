/*
 *  Copyright (c) 2012-2019, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

/*
 * Refer to bloom.h for documentation on the public interfaces.
 */

#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>

#include "bloom.h"
#include "../xxhash/xxhash.h"

#define MAKESTRING(n) STRING(n)
#define STRING(n) #n
#define BLOOM_MAGIC "libbloom2"
#define BLOOM_VERSION_MAJOR 2
#define BLOOM_VERSION_MINOR 201

inline static int test_bit_set_bit(uint8_t *bf, uint64_t bit, int set_bit)
{
  uint64_t byte = bit >> 3;
  uint8_t c = bf[byte];	 // expensive memory access
  uint8_t mask = 1 << (bit % 8);
  if (c & mask) {
    return 1;
  } else {
    if (set_bit) {
		bf[byte] = c | mask;
    }
    return 0;
  }
}

inline static int test_bit(uint8_t *bf, uint64_t bit)
{
  uint64_t byte = bit >> 3;
  uint8_t c = bf[byte];	 // expensive memory access
  uint8_t mask = 1 << (bit % 8);
  if (c & mask) {
    return 1;
  } else {
    return 0;
  }
}

static int bloom_check_add(struct bloom * bloom, const void * buffer, int len, int add)
{
  if (bloom->ready == 0) {
    printf("bloom at %p not initialized!\n", (void *)bloom);
    return -1;
  }
  uint8_t hits = 0;
  uint64_t a = XXH64(buffer, len, 0x59f2815b16f81798);
  uint64_t b = XXH64(buffer, len, a);
  uint64_t x;
  uint8_t i;
  for (i = 0; i < bloom->hashes; i++) {
    x = (a + b*i) % bloom->bits;
    if (test_bit_set_bit(bloom->bf, x, add)) {
      hits++;
    } else if (!add) {
      // Don't care about the presence of all the bits. Just our own.
      return 0;
    }
  }
  if (hits == bloom->hashes) {
    return 1;                // 1 == element already in (or collision)
  }
  return 0;
}

// DEPRECATED - Please migrate to bloom_init2.
int bloom_init(struct bloom * bloom, uint64_t entries, long double error)
{
  return bloom_init2(bloom, entries, error);
}

int bloom_init2(struct bloom * bloom, uint64_t entries, long double error)
{
  memset(bloom, 0, sizeof(struct bloom));
  if (entries < 1000 || error <= 0 || error >= 1) {
    return 1;
  }
  bloom->entries = entries;
  bloom->error = error;

  long double num = -log(bloom->error);
  long double denom = 0.480453013918201; // ln(2)^2
  bloom->bpe = (num / denom);

  long double dentries = (long double)entries;
  long double allbits = dentries * bloom->bpe;
  bloom->bits = (uint64_t)allbits;

  bloom->bytes = (uint64_t) bloom->bits / 8;
  if (bloom->bits % 8) {
    bloom->bytes +=1;
  }

  bloom->hashes = (uint8_t)ceil(0.693147180559945 * bloom->bpe);  // ln(2)
  
  bloom->bf = (uint8_t *)calloc(bloom->bytes, sizeof(uint8_t));
  if (bloom->bf == NULL) {                                   // LCOV_EXCL_START
    return 1;
  }                                                          // LCOV_EXCL_STOP

  bloom->ready = 1;
  bloom->major = BLOOM_VERSION_MAJOR;
  bloom->minor = BLOOM_VERSION_MINOR;
  return 0;
}

int bloom_check(struct bloom * bloom, const void * buffer, int len)
{
  if (bloom->ready == 0) {
    printf("bloom at %p not initialized!\n", (void *)bloom);
    return -1;
  }
  uint8_t hits = 0;
  uint64_t a = XXH64(buffer, len, 0x59f2815b16f81798);
  uint64_t b = XXH64(buffer, len, a);
  uint64_t x;
  uint8_t i;
  for (i = 0; i < bloom->hashes; i++) {
    x = (a + b*i) % bloom->bits;
    if (test_bit(bloom->bf, x)) {
      hits++;
    } else {
      return 0;
    }
  }
  if (hits == bloom->hashes) {
    return 1;                // 1 == element already in (or collision)
  }
  return 0;
}


int bloom_add(struct bloom * bloom, const void * buffer, int len)
{
  return bloom_check_add(bloom, buffer, len, 1);
}

void bloom_print(struct bloom * bloom)
{
  printf("bloom at %p\n", (void *)bloom);
  if (!bloom->ready) { printf(" *** NOT READY ***\n"); }
  printf(" ->version = %d.%d\n", bloom->major, bloom->minor);
  printf(" ->entries = %" PRIu64 "\n", bloom->entries);
  printf(" ->error = %Lf\n", bloom->error);
  printf(" ->bits = %" PRIu64 "\n", bloom->bits);
  printf(" ->bits per elem = %f\n", bloom->bpe);
  printf(" ->bytes = %" PRIu64 "\n", bloom->bytes);
  unsigned int KB = bloom->bytes / 1024;
  unsigned int MB = KB / 1024;
  printf(" (%u KB, %u MB)\n", KB, MB);
  printf(" ->hash functions = %d\n", bloom->hashes);
}

void bloom_free(struct bloom * bloom)
{
  if (bloom->ready) {
    free(bloom->bf);
  }
  bloom->ready = 0;
}

int bloom_reset(struct bloom * bloom)
{
  if (!bloom->ready) return 1;
  memset(bloom->bf, 0, bloom->bytes);
  return 0;
}
/*
int bloom_save(struct bloom * bloom, char * filename)
{
  if (filename == NULL || filename[0] == 0) {
    return 1;
  }

  int fd = open(filename, O_WRONLY | O_CREAT, 0644);
  if (fd < 0) {
    return 1;
  }

  ssize_t out = write(fd, BLOOM_MAGIC, strlen(BLOOM_MAGIC));
  if (out != strlen(BLOOM_MAGIC)) { goto save_error; }        // LCOV_EXCL_LINE

  uint16_t size = sizeof(struct bloom);
  out = write(fd, &size, sizeof(uint16_t));
  if (out != sizeof(uint16_t)) { goto save_error; }           // LCOV_EXCL_LINE

  out = write(fd, bloom, sizeof(struct bloom));
  if (out != sizeof(struct bloom)) { goto save_error; }       // LCOV_EXCL_LINE

  out = write(fd, bloom->bf, bloom->bytes);
  if (out != bloom->bytes) { goto save_error; }               // LCOV_EXCL_LINE

  close(fd);
  return 0;
                                                             // LCOV_EXCL_START
 save_error:
  close(fd);
  return 1;
                                                             // LCOV_EXCL_STOP
}


int bloom_load(struct bloom * bloom, char * filename)
{
  int rv = 0;

  if (filename == NULL || filename[0] == 0) { return 1; }
  if (bloom == NULL) { return 2; }

  memset(bloom, 0, sizeof(struct bloom));

  int fd = open(filename, O_RDONLY);
  if (fd < 0) { return 3; }

  char line[30];
  memset(line, 0, 30);
  ssize_t in = read(fd, line, strlen(BLOOM_MAGIC));

  if (in != strlen(BLOOM_MAGIC)) {
    rv = 4;
    goto load_error;
  }

  if (strncmp(line, BLOOM_MAGIC, strlen(BLOOM_MAGIC))) {
    rv = 5;
    goto load_error;
  }

  uint16_t size;
  in = read(fd, &size, sizeof(uint16_t));
  if (in != sizeof(uint16_t)) {
    rv = 6;
    goto load_error;
  }

  if (size != sizeof(struct bloom)) {
    rv = 7;
    goto load_error;
  }

  in = read(fd, bloom, sizeof(struct bloom));
  if (in != sizeof(struct bloom)) {
    rv = 8;
    goto load_error;
  }

  bloom->bf = NULL;
  if (bloom->major != BLOOM_VERSION_MAJOR) {
    rv = 9;
    goto load_error;
  }

  bloom->bf = (unsigned char *)malloc(bloom->bytes);
  if (bloom->bf == NULL) { rv = 10; goto load_error; }        // LCOV_EXCL_LINE

  in = read(fd, bloom->bf, bloom->bytes);
  if (in != bloom->bytes) {
    rv = 11;
    free(bloom->bf);
    bloom->bf = NULL;
    goto load_error;
  }

  close(fd);
  return rv;

 load_error:
  close(fd);
  bloom->ready = 0;
  return rv;
}
*/

const char * bloom_version()
{
  return MAKESTRING(BLOOM_VERSION);
}
