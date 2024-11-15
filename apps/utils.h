#ifndef UTILS_H
#define UTILS_H

#include <stdint.h> //integer type


uint64_t rand64(void);
uint64_t randmod(uint64_t mod);

void print_binary_form(uint64_t in);

// For 128-bit integer

void     Mult128    (uint64_t *out1, uint64_t *out2, uint64_t in1, uint64_t in2);
void     Add128     (uint64_t *out1, uint64_t *out2, uint64_t in11, uint64_t in12, uint64_t in21, uint64_t in22);
void     Mult128Bi  (uint64_t *outup, uint64_t *outdown, uint64_t in1up, uint64_t in1down, uint64_t in2up, uint64_t in2down);

// modular op;

uint64_t subq(uint64_t ina, uint64_t inb, uint64_t mod);
#endif