#ifndef SECFPR_H
#define SECFPR_H

#include <stddef.h>
#include <stdint.h>

#include "gadgets.h"


void SecFprScalPtwo(maskedb_t out, maskedb_t in1, uint16_t ptwo);
void SecFprDivPtwo(maskedb_t out, maskedb_t in1, uint16_t ptwo);

void SecFprFloor(maskedb_t out, maskedb_t in);
void SecFprTrunc(maskedb_t out, maskedb_t in);
void SecFprInv(maskedb_t out, maskedb_t in);

void SecApproxExp(maskedb_t out, maskedb_t x, maskedb_t ccs);
uint64_t SecFprBerExp(maskedb_t out, maskedb_t x, maskedb_t ccs, maskedb_t alea);

void BaseSampler(maskedb_t out);
void SamplerZ(maskedb_t out, maskedb_t mu, maskedb_t sig);

#endif