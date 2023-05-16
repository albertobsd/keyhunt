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
	
	//char *ptrs[3];
	mpz_set(x.num,p.x.num);
	mpz_set(y.num,p.y.num);
	mpz_set(z.num,p.z.num);
	/*
	ptrs[0] = x.GetBase16();
	ptrs[1] = y.GetBase16();
	ptrs[2] = z.GetBase16();
	printf("Point\n");
	printf("X: %s\n",ptrs[0]);
	printf("Y: %s\n",ptrs[1]);
	printf("Z: %s\n",ptrs[2]);
	printf("End Point\n");
	for(int i = 0; i<3; i++)	{
		free(ptrs[i]);
	}
	*/
}

Point::Point(Int *cx,Int *cy,Int *cz) {
	mpz_set(x.num,cx->num);
	mpz_set(y.num,cy->num);
	mpz_set(z.num,cz->num);
}

/*
Point::Point(Int *cx, Int *cz) {
  x.Set(cx);
  z.Set(cz);
}
*/

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
/*
Yes, exactly. The Reduce function you mentioned converts the point from projective coordinates back to affine coordinates.

In elliptic curve computations, it's often more efficient to work with projective coordinates because they allow addition and doubling operations to be performed without needing to do division operations, which are computationally expensive.

However, at the end of your computation, or at certain intermediate stages, you might need to convert the point back to affine coordinates. That's what this Reduce function is doing.

Here's what each line in Reduce is doing:

Int i(&z); creates an integer i from the z coordinate of the point.
i.ModInv(); computes the modular inverse of i, effectively performing a division operation. Note that this operation is only valid if i is not zero.
x.ModMul(&x,&i); and y.ModMul(&y,&i); multiply the x and y coordinates by the modular inverse of z, effectively dividing them by z. This converts the x and y coordinates from projective back to affine coordinates.
z.SetInt32(1); sets the z coordinate to 1, completing the conversion to affine coordinates.
In the end, Reduce leaves the point in the form (X/Z, Y/Z, 1), which is equivalent to (X, Y) in affine coordinates.
*/  
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
	//char *ptrs[3];
	// Assign the values from 'other' to the current object
	mpz_set(x.num,other.x.num);
	mpz_set(y.num,other.y.num);
	mpz_set(z.num,other.z.num);
	/*
	ptrs[0] = x.GetBase16();
	ptrs[1] = y.GetBase16();
	ptrs[2] = z.GetBase16();
	printf("Point\n");
	printf("X: %s\n",ptrs[0]);
	printf("Y: %s\n",ptrs[1]);
	printf("Z: %s\n",ptrs[2]);
	printf("End Point\n");
	for(int i = 0; i<3; i++)	{
		free(ptrs[i]);
	}
	*/
	// Return the current object
	return *this;
}

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