#ifndef GADGETS_H
#define GADGETS_H

#include <stddef.h> 
#include <stdint.h> 


#define MASKORDER 1UL
#define MASKSIZE MASKORDER+1UL

typedef uint64_t maskeda_t[MASKSIZE];
typedef uint64_t maskedb_t[MASKSIZE];


void MaskB (maskedb_t out, uint64_t in);
void UnmaskB (uint64_t *out, maskedb_t in);

void SecAnd (maskedb_t out, maskedb_t ina, maskedb_t inb, size_t size);

void RefreshXOR(maskedb_t out, maskedb_t in, uint64_t k2, size_t size);
void RefreshXOR_64(maskedb_t out, maskedb_t in, size_t size);
void RefreshMasks(maskedb_t out, size_t size);
void SecAdd(uint64_t *out, uint64_t *ina, uint64_t* inb, size_t size);

void MaskA(maskeda_t out, uint64_t in, uint64_t mod);
void UnmaskA(uint64_t *out, maskeda_t in, uint64_t mod);

void SecMult(maskeda_t out, maskeda_t ina, maskeda_t inb, uint64_t mod);

void A2B(maskedb_t out, maskeda_t in, uint64_t mod);
void B2A(uint64_t *out, uint64_t *in, uint64_t mod, size_t size);
void B2A_bit(maskeda_t A, maskedb_t b, uint64_t mod);

//-----------------------for 128-bit length value----------------------------

void SecMult128(maskeda_t outup,maskeda_t outdown, maskeda_t inaup, maskeda_t inadown,maskeda_t inbup,maskeda_t inbdown);
void SecAdd128(uint64_t *out1,uint64_t *out, uint64_t *ina1,uint64_t *ina, uint64_t* inb1,uint64_t *inb, size_t size);

void A2B128(uint64_t *out1,uint64_t *out2, uint64_t *in1, uint64_t *in2, size_t size);
void B2A128(maskeda_t outup, maskeda_t outdown, maskedb_t inup, maskedb_t indown, size_t size);


#endif
