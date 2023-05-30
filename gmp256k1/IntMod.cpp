#include "Int.h"

static Int     _P;					// Field characteristic
static Int _R2o;					// R^2 for SecpK1 order modular mult
static Int *_O;   					// Field Order

void Int::Mod(Int *A) {	
	mpz_mod(num,num,A->num);
}

void Int::ModInv() {	
	mpz_invert(num,num,_P.num);
}

void Int::ModNeg() {
	mpz_neg(num,num);
	mpz_add(num,num,_P.num);
}

void Int::ModAdd(Int *a) {
	mpz_t p;
	mpz_add(num,num,a->num);
	mpz_init_set(p,num);
	mpz_sub(p,p,_P.num);
	if(mpz_cmp_ui(p,0) >= 0)
		mpz_set(num,p);
	mpz_clear(p);
}


void Int::ModAdd(uint32_t a) {
	mpz_t p;
	mpz_add_ui(num,num,a);
	mpz_init_set(p,num);
	mpz_sub(p,p,_P.num);
	if(mpz_cmp_ui(p,0) >= 0)
		mpz_set(num,p);
	mpz_clear(p);
}

void Int::ModAdd(Int *a, Int *b) {
	mpz_t p;
	mpz_add(num,a->num,b->num);
	mpz_init_set(p,num);
	mpz_sub(p,p,_P.num);
	if(mpz_cmp_ui(p,0) >= 0)
		mpz_set(num,p);
	mpz_clear(p);
}

void Int::ModMul(Int *a)	{	// this <- this*b (mod n)
	mpz_mul(num,num,a->num);
	mpz_mod(num,num,_P.num);
}

void Int::ModMul(Int *a,Int *b)	{                // this <- a*b (mod n)
	mpz_mul(num,a->num,b->num);
	mpz_mod(num,num,_P.num);
}

void Int::ModSub(Int *a) {
	mpz_sub(num,num,a->num);
	if (mpz_cmp_ui(num,0) < 0 )
		mpz_add(num,num,_P.num);
}

void Int::ModSub(Int *a,Int *b) {
	mpz_sub(num,a->num,b->num);
	if (mpz_cmp_ui(num,0) < 0 )
		mpz_add(num,num,_P.num);
}

void Int::ModSub(uint64_t a) {
	Int A(a);
	mpz_add(num,num,A.num);
	if (mpz_cmp_ui(num,0) < 0)
		mpz_add(num,num,_P.num);
}


void Int::ModMulK1(Int *a, Int *b)	{
	mpz_mul(num,a->num,b->num);
	mpz_mod(num,num,_P.num);
}

void Int::ModMulK1(Int *a)	{
	mpz_mul(num,num,a->num);
	mpz_mod(num,num,_P.num);
}



void Int::ModSquareK1(Int *a)	{
	mpz_powm_ui(num,a->num,2,_P.num);
}

void Int::ModDouble()	{
	mpz_t p;
	mpz_add(num,num,num);
	mpz_init_set(p,num);
	mpz_sub(p,p,_P.num);
	if(mpz_cmp_ui(p,0) > 0)	{
		mpz_set(num,p);
	}
	mpz_clear(p);
}

void Int::ModSqrt()	{
	mpz_sqrt(num,num);
	mpz_mod(num,num,_P.num);
}

bool Int::HasSqrt()	{
	if(mpz_perfect_square_p(num) != 0)
		return true;
	return false;
}


/* Initializator  of some Values P and N (Order) */

void Int::SetupField(Int *n) {
	_P.Set(n);
}

void Int::InitK1(Int *order) {
  _O = order;
  _R2o.SetBase16("9D671CD581C69BC5E697F5E45BCD07C6741496C20E7CF878896CF21467D7D140");
}

/* This next Opeations that have endin in order are modulo N */

void Int::ModMulK1order(Int *a)	{
	mpz_mul(num,num,a->num);
	mpz_mod(num,num,_O->num);
}

void Int::ModAddK1order(Int *a, Int *b) {
	mpz_add(num,num,a->num);
	mpz_add(num,num,b->num);
	mpz_sub(num,num,_O->num);
	if (mpz_cmp_ui(num,0) < 0 )
		mpz_add(num,num,_O->num);
}

void Int::ModInvorder() {	
	mpz_invert(num,num,_O->num);
}
