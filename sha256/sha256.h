/*
    SHA256 implementation, header file.

    This implementation was written by Kent "ethereal" Williams-King and is
    hereby released into the public domain. Do what you wish with it.

    No guarantees as to the correctness of the implementation are provided.
*/

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

void sha256(const void *data, uint64_t len, void *output);

#endif
