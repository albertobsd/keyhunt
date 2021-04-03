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

#ifndef INTGROUPH
#define INTGROUPH

#include "Int.h"
#include <vector>

class IntGroup {

public:

	IntGroup(int size);
	~IntGroup();
	void Set(Int *pts);
	void ModInv();

private:

	Int *ints;
  Int *subp;
  int size;

};

#endif // INTGROUPCPUH
