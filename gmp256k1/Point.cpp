/*
 * This file is part of the BSGS distribution (https://github.com/JeanLucPons/BSGS).
 * Copyright (c) 2020 Jean Luc PONS.
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

#include "Point.h"
#include <stdio.h>

Point::Point() {
}

Point::Point(const Point &p) {

	mpz_set(x.num,p.x.num);
	mpz_set(y.num,p.y.num);
	mpz_set(z.num,p.z.num);
}

Point::Point(Int *cx,Int *cy,Int *cz) {
	mpz_set(x.num,cx->num);
	mpz_set(y.num,cy->num);
	mpz_set(z.num,cz->num);
}

void Point::Clear() {
	mpz_set_ui(x.num,0);
	mpz_set_ui(y.num,0);
	mpz_set_ui(z.num,0);
}

void Point::Set(Int *cx, Int *cy,Int *cz) {
	mpz_set(x.num,cx->num);
	mpz_set(y.num,cy->num);
	mpz_set(z.num,cz->num);
}

Point::~Point() {

}

void Point::Set(Point &p) {
	mpz_set(x.num,p.x.num);
	mpz_set(y.num,p.y.num);
	mpz_set(z.num,p.z.num);
}

bool Point::isZero() {
	return x.IsZero() && y.IsZero();
}

void Point::Reduce() {
	Int i(&z);
	i.ModInv();
	x.ModMul(&x,&i);
	y.ModMul(&y,&i);
	z.SetInt32(1); 
}

bool Point::equals(Point &p) {
	return x.IsEqual(&p.x) && y.IsEqual(&p.y) && z.IsEqual(&p.z);
}

// Copy assignment operator
Point& Point::operator=(const Point& other)  {
	// Check for self-assignment
	if (this == &other) {
		return *this;
	}
	// Assign the values from 'other' to the current object
	mpz_set(x.num,other.x.num);
	mpz_set(y.num,other.y.num);
	mpz_set(z.num,other.z.num);

	// Return the current object
	return *this;
}

/*
void Point::print(const char *str)	{
	char *ptrs[3];
	ptrs[0] = x.GetBase16();
	ptrs[1] = y.GetBase16();
	ptrs[2] = z.GetBase16();
	printf("Point %s\n",str);
	printf("X: %s\n",ptrs[0]);
	printf("Y: %s\n",ptrs[1]);
	printf("Z: %s\n",ptrs[2]);
	printf("End Point\n");
	for(int i = 0; i<3; i++)	{
		free(ptrs[i]);
	}
}
*/