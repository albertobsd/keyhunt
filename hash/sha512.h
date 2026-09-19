/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SHA512_H
#define SHA512_H

/* Cross-platform: MSVC only predefines _WIN64 on 64-bit Windows, but this
   codebase gates its Windows-specific paths on the bare macro WIN64.
   Normalize it so the sources build with MSVC (and MinGW) without relying
   on a build-system -DWIN64 flag. */
#if defined(_WIN64) && !defined(WIN64)
#define WIN64
#endif

#include <string>

void sha512(unsigned char *input, int length, unsigned char *digest);
void pbkdf2_hmac_sha512(uint8_t *out, size_t outlen,const uint8_t *passwd, size_t passlen,const uint8_t *salt, size_t saltlen,uint64_t iter);
void hmac_sha512(unsigned char *key, int key_length, unsigned char *message, int message_length, unsigned char *digest);

std::string sha512_hex(unsigned char *digest);

#endif
