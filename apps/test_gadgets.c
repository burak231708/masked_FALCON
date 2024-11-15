#include <stdio.h>


#include "gadgets.h"
#include "utils.h"


#define MOD (1UL<<15)

int main(void){
    //declaration
    uint64_t res = rand64()%MOD;
    uint64_t res1 = rand64()%MOD;
    uint64_t res2;
    uint64_t res_m1 = 0;
    maskedb_t m1, m2, m3;
    maskeda_t m4, m5, m6;
    //uint64_t a128, b128, c128, d128;


    printf("-------------------------------test_maskB---------------------------------\n");
    printf("\n");

    printf("res   = %lu\n", res);
    
    MaskB(m1, res);

    UnmaskB(&res_m1, m1);

    printf("res_m = %lu\n", res_m1);

    printf("-----------------------------test_operation--------------------------------\n");
    printf("\n");
    printf("SecAnd :\n");
    MaskB(m1, res1);
    printf("res1  = %lu\n", res1);
    print_binary_form(res1);
    res2 = rand64()%MOD;
    MaskB(m2, res2);
    printf("res2  = %lu\n", res2);
    print_binary_form(res2);

    SecAnd(m3, m1, m2, MASKSIZE);
    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);


    printf("\nSecAdd :\n");
    printf("res1  = %lu\n", res1);
    print_binary_form(res1);
    printf("res2  = %lu\n", res2);
    print_binary_form(res2);

    SecAdd(m3, m1, m2, MASKSIZE);
    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    printf("-------------------------------test_maskA---------------------------------\n");
    printf("\n");

    res = rand64();
    printf("res   = %lu\n", res);
    print_binary_form(res);
    
    MaskA(m4, res, MOD);

    UnmaskA(&res_m1, m4, MOD);

    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    printf("-----------------------------test_operation--------------------------------\n");
    printf("\n");

    printf("SecMult :\n");
    MaskA(m4, res1, MOD);
    printf("res1  = %lu\n", res1);
    print_binary_form(res1);
    res2 = rand64()%MOD;
    MaskA(m5, res2, MOD);
    printf("res2  = %lu\n", res2);
    print_binary_form(res2);

    SecMult(m6, m4, m5, MOD);
    UnmaskA(&res_m1, m6, MOD);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    printf("res1 * res2 = %lu \n", ((res1 % MOD) * (res2 % MOD)) % MOD);
    print_binary_form(((res1 % MOD) * (res2 % MOD)) % MOD);


    printf("-----------------------------test_convertion--------------------------------\n");
    printf("\n");

    UnmaskA(&res1, m4, MOD);
    printf("res1  = %lu\n", res1);
    print_binary_form(res1);


    A2B(m1, m4, MOD);
    UnmaskB(&res1, m1);
    printf("res1  = %lu\n", res1);
    print_binary_form(res1);

    B2A(m5, m1, MOD, MASKSIZE);

    UnmaskA(&res1, m4, MOD);
    printf("res1  = %lu\n", res1);
    print_binary_form(res1);


    // b128 = -(1UL);//(1UL<<63);
    // Mult128(&c128, &d128, a128, b128);

    // print_binary_form(a128);
    // print_binary_form(b128);
    // print_binary_form(c128);
    // print_binary_form(d128);

    return 0;
}