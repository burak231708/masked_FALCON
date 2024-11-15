#ifndef CHENCHEN_GADGETS_H
#define CHENCHEN_GADGETS_H

#include <stddef.h> // pour size_t (à voir si on en a vraiment besoin)
#include <stdint.h> //integer type

#include "gadgets.h"



void SecOr (maskedb_t out, maskedb_t ina, maskedb_t inb);
void SecNonZeroB(maskedb_t out, maskedb_t in);

void SecFprUrsh(maskedb_t out, maskedb_t x, maskeda_t c);
//void SecFprUrsh2(maskedb_t out, maskedb_t in, maskeda_t c);
//void SecFprUrsh3(maskedb_t out, maskedb_t out2, maskedb_t in, maskeda_t c);
void SecFprNorm64(maskedb_t x, maskeda_t e, uint64_t);

void SecFpr(maskedb_t x, maskedb_t s, maskeda_t e, maskedb_t m);

void SecFprMul(maskedb_t out, maskedb_t x, maskedb_t y);

void SecFprAdd(maskedb_t out, maskedb_t in1, maskedb_t in2);

#endif