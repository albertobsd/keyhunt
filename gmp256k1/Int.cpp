/*
 * This file is part of the Keyhunt distribution (https://github.com/albertobsd/keyhunt).
 * Copyright (c) 2023 albertobsd.
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

// Big integer class (libgmp)

#include "Int.h"
#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include<gmp.h>

#define U64STRINGSIZE 30

Int::Int() {
	mpz_init_set_ui(num,0);
}

Int::Int(const int32_t i32)	{
	mpz_init_set_si(num,i32);
}

Int::Int(const uint32_t u32)	{
	mpz_init_set_ui(num,u32);
}

Int::Int(const Int *other)	{
	mpz_init_set(num,other->num);
}

Int::Int(const char *str)	{
	mpz_init_set_str(num,str,0);
}

Int::Int(const uint64_t u64)	{
	char my_str_value[U64STRINGSIZE]; // 30 digits + null terminator
	snprintf(my_str_value,U64STRINGSIZE, "%lu", u64);
	mpz_init_set_str(num,my_str_value,0);
}

Int::Int(const int64_t i64)	{
	char my_str_value[U64STRINGSIZE]; // 30 digits + null terminator
	snprintf(my_str_value,U64STRINGSIZE,"%li", i64);
	mpz_init_set_str(num,my_str_value,0);
}

Int::Int(const Int &value)	{
	mpz_init_set(num,value.num);
}


void Int::Add(const uint64_t u64)	{
	mpz_t value;
	char my_str_value[U64STRINGSIZE]; // 30 digits + null terminator
	snprintf(my_str_value,U64STRINGSIZE,"%lu", u64);
	mpz_init_set_str(value,my_str_value,0);
	mpz_add(num,num,value);
	mpz_clear(value);
}

void Int::Add(const uint32_t u32)	{
	mpz_add_ui(num,num,u32);
}

void Int::Add(const Int *a)	{
	mpz_add(num,num,a->num);
}

void Int::Add(const Int *a,const Int *b)	{
	mpz_add(num,a->num,b->num);
}

void Int::Sub(const uint32_t u32)	{
	mpz_sub_ui(num,num,u32);
}

void Int::Sub(const uint64_t u64)	{
	mpz_t value;
	char my_str_value[U64STRINGSIZE]; // 30 digits + null terminator
	snprintf(my_str_value,U64STRINGSIZE,"%lu", u64);
	mpz_init_set_str(value,my_str_value,0);
	mpz_sub(num,num,value);
	mpz_clear(value);
}

void Int::Sub(Int *a)	{
	mpz_sub(num,num,a->num);
}

void Int::Sub(Int *a, Int *b)	{
	mpz_sub(num,a->num,b->num);
}

void Int::Mult(Int *a)	{
	mpz_mul(num,num,a->num);
}

void Int::Mult(uint64_t u64)	{
	mpz_t value;
	char my_str_value[U64STRINGSIZE]; // 30 digits + null terminator
	snprintf(my_str_value,U64STRINGSIZE,"%lu", u64);
	mpz_init_set_str(value,my_str_value,0);
	mpz_mul(num,num,value);
	mpz_clear(value);
}

void Int::IMult(int64_t i64)	{
	mpz_t value;
	char my_str_value[U64STRINGSIZE]; // 30 digits + null terminator
	snprintf(my_str_value,U64STRINGSIZE,"%li", i64);
	mpz_init_set_str(value,my_str_value,0);
	mpz_mul(num,num,value);
	mpz_clear(value);
}

void Int::Neg()	{
	mpz_neg(num,num);
}

void Int::Abs()	{
	mpz_abs(num,num);
}

bool Int::IsGreater(Int *a)	{
	if(mpz_cmp(num,a->num) > 0)
		return true;
	return false;
}

bool Int::IsGreaterOrEqual(Int *a)	{
	if(mpz_cmp(num,a->num) >= 0)
		return true;
	return false;	
}

bool Int::IsLowerOrEqual(Int *a)	{
	if(mpz_cmp(num,a->num) <= 0)
		return true;
	return false;
}

bool Int::IsLower(Int *a)	{
	if(mpz_cmp(num,a->num) < 0)
		return true;
	return false;
}

bool Int::IsEqual(Int *a)	{
	if(mpz_cmp(num,a->num) == 0)
		return true;
	return false;
}

bool Int::IsZero()	{
	if(mpz_cmp_ui(num,0) == 0)
		return true;
	return false;
}

bool Int::IsOne()	{
	if(mpz_cmp_ui(num,1) == 0)
		return true;
	return false;
}

bool Int::IsPositive()	{
	if(mpz_cmp_ui(num,0) >= 0)
		return true;
	return false;
}

bool Int::IsNegative()	{
	if(mpz_cmp_ui(num,0) < 0)
		return true;
	return false;
}

bool Int::IsEven()	{
	if(mpz_tstbit(num,0) == 0)
		return true;
	return false;
}

bool Int::IsOdd()	{
	if(mpz_tstbit(num,0) == 1)
		return true;
	return false;
}
	
int Int::GetSize()	{
	int r = mpz_sizeinbase(num,2);
	if(r % 8 == 0)
		return (int)(r/8);
	else
		return (int)(r/8) + 1;
}

int Int::GetBitLength()	{
	return mpz_sizeinbase(num,2);
}

uint64_t Int::GetInt64()	{
	char *temp =NULL;
	uint64_t r;
	temp = mpz_get_str(NULL,10,num);
	r = strtoull(temp,NULL,10);
	free(temp);
	return r;
}

uint32_t Int::GetInt32()	{
	return mpz_get_ui(num);
}

int Int::GetBit(uint32_t n)	{
	return mpz_tstbit(num,n);
}

void Int::SetBit(uint32_t n)	{
	mpz_setbit(num,n);
}

void Int::ClearBit(uint32_t n)	{
	mpz_clrbit(num,n);
}


void Int::Get32Bytes(unsigned char *buff)	{
	size_t count, size = this->GetSize();
	memset(buff, 0, 32);
	mpz_export(buff + 32 - size, &count, 0, 1, 0, 0, num);
}

void Int::Set32Bytes(unsigned char *buff)	{
	mpz_import(num,32,0,1,0,0,buff);
}

unsigned char Int::GetByte(int n)	{
	unsigned char buffer[32];
	size_t count, size = this->GetSize();
	memset(buffer, 0, 32);
	mpz_export(buffer + 32 - size, &count, 0, 1, 0, 0, num);
	return buffer[n];
}

char* Int::GetBase2()	{
	return mpz_get_str(NULL,2,num);
}

char* Int::GetBase10()	{
	return mpz_get_str(NULL,10,num);
}

char* Int::GetBase16()	{
	return mpz_get_str(NULL,16,num);
}

void Int::SetInt64(uint64_t value)	{
	char my_str_value[U64STRINGSIZE]; // 30 digits + null terminator
	snprintf(my_str_value, U64STRINGSIZE, "%lu", value);
	mpz_set_str(num,my_str_value,0);
}

void Int::SetInt32(const uint32_t value)	{
	mpz_set_ui(num,value);
}

void Int::Set(const Int* other)	{
	mpz_set(num,other->num);
}

void Int::Set(const char *str)	{
	mpz_set_str(num,str,0);
}

void Int::SetBase10(const char *str)	{
	mpz_set_str(num,str,10);
}

void Int::SetBase16(const char *str)	{
	mpz_set_str(num,str,16);
}

Int::~Int() {
	mpz_clear(num);
}

// Copy assignment operator
Int& Int::operator=(const Int& other)  {
	// Check for self-assignment
	if (this == &other) {
		return *this;
	}

	// Assign the values from 'other' to the current object
	mpz_set(num,other.num);

	// Return the current object
	return *this;
}

void Int::AddOne() {
	mpz_add_ui(num,num,1);
}

void Int::ShiftL(uint32_t n)	{
	mpz_mul_2exp(num,num,n);
	
}

void Int::Div(Int *a,Int *mod) {
	if(mpz_cmp(num,a->num) < 0)	{
		if(mod) mpz_set(mod->num,num);
		CLEAR();
		return;
	}
	if(mpz_cmp_ui(a->num,0) == 0)	{
		printf("Divide by 0!\n");
		return;
	}

	if(mpz_cmp(num,a->num) == 0) {
		if(mod) mod->CLEAR();
		mpz_set_ui(num,1);
		return;
	}
	if(mod)	{
		mpz_fdiv_qr (num, mod->num, num, a->num);
	}
	else	{
		mpz_fdiv_q(num,num,a->num);
	}
}

void Int::CLEAR() {
	mpz_set_ui(num,0);
}