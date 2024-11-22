#include <stdio.h>

#include "fpr_gadgets.h"
#include "gadgets.h"
#include "utils.h"


#define MOD (1UL<<15)
#define MOD64 64

int main(void){
    //declaration
    uint64_t res1 = rand64()%MOD;
    uint64_t res2 = rand64()%MOD;
    uint64_t res_m1 = 0;
    maskedb_t m1, m2, m3;
    maskeda_t m4/*, m5, m6*/;
    size_t i = 0;
    uint64_t test = 0;

    maskedb_t /*s,sbx,sby,*/p1,p2,/*b,z,z2,w,w2,bx,by,d,*/ebx,eby,mbxu,mbxd,mbyu,mbyd, b1,b2;
    maskeda_t /*e,*/eax,eay/*,wa,p3,p4*/,mxu,mxd,myu,myd;
    //uint64_t a128, b128, c128, d128;


    printf("-------------------------------test_FPR_Gadgets---------------------------------\n");
    printf("\n");

    printf("\n                    SecOr  :\n");
    printf("res1  = %lu\n", res1);
    print_binary_form(res1);
    printf("res2  = %lu\n", res2);
    print_binary_form(res2);
    MaskB(m1, res1);
    MaskB(m2, res2);

    SecOr(m3, m1, m2);
    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    printf("\n                    SecNonZeroB (random test):\n");
    MaskB(m1, res1);
    printf("res1  = %lu\n", res1);
    print_binary_form(res1);

    SecNonZeroB(m3, m1);
    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);


    printf("\n                    SecNonZeroB (test 0):\n");
    MaskB(m1, 0);
    printf("res1  = %lu\n", 0UL);
    print_binary_form(0);

    SecNonZeroB(m3, m1);
    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    printf("\n                    SecNonZeroB (test 2^i):\n");
    printf("expected result = 1 :\n");
    for (i = 0; i<64; i++){
        res1 = 1UL << i;
        MaskB(m1, res1);
        SecNonZeroB(m3, m1);
        UnmaskB(&res_m1, m3);
        if ((res_m1 == 0)){
            test += 1;
        }
    }
    if (test == 0){
        printf("result = 1, test is valid\n\n");
    }else{
        printf("error's number = %lu\n\n", test);
    }


    printf("                    SecFprUrsh (random test):\n");

    res1 = rand64();
    MaskB(m1, res1);
    printf("res1  = %lu\n", res1);
    print_binary_form(res1);

    res2 = rand64();
    MaskA(m4, res2, MOD64);
    printf("res2  = %lu\n", res2);
    print_binary_form(res2);
    UnmaskA(&res_m1, m4, MOD64);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    SecFprUrsh(m3, m1, m4);

    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);


    printf("\n                    SecFprNorm64  (test 5)\n");

    res1 = 0x0140000000000000;
    MaskB(m1, res1);
    print_binary_form(res1);

    res2 = 1023UL;
    MaskA(m4, res2, 1<<16);
    print_binary_form(1023);

    SecFprNorm64(m1,m4,1<<16);

    UnmaskB(&res_m1, m1);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    UnmaskA(&res_m1, m4, 1<<16);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);


    printf("\n                    SecFprMult (test 5x5):\n");
    res1 = (0UL << 63) + (0x401UL << 52) + (0x4000000000000UL);
    res2 = res1;
    print_binary_form(res1);
    MaskB(m1, res1);
    MaskB(m2, res2);
    SecFprMul(m3, m1, m2);
    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    printf("\n                    SecFprAdd  (test 5+5):\n");
    res1 = (0UL << 63) + (0x401UL << 52) + (0x4000000000000UL);
    res2 = res1;
    print_binary_form(res1);
    MaskB(m1, res1);
    MaskB(m2, res2);
    SecFprAdd(m3, m1, m2);
    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);


    printf("\n                    Conversion (test FPR(5)):\n");
    //EXTRACTION
    for(i =0; i < MASKSIZE;i++){
        ebx[i] = ((m1[i]<<1)>>53);
        eby[i] = ((m2[i]<<1)>>53);
        mbxd[i] = m1[i] & 0xfffffffffffff;
        mbxu[i]=0;
        mbyd[i] = m2[i] & 0xfffffffffffff;
        mbyu[i]=0;
    }
    SecNonZeroB(b1, m1);
    SecNonZeroB(b2, m2);
    for(i = 0; i<MASKSIZE; i++){
        mbxd[i] = mbxd[i] ^ (b1[i]<<52);
        mbyd[i] = mbyd[i] ^ (b2[i]<<52);
    }

    B2A(eax,ebx,(1<<16),MASKSIZE);
    B2A128(mxu,mxd,mbxu,mbxd,MASKSIZE);
    B2A(eay,eby,(1<<16),MASKSIZE);
    B2A128(myu,myd,mbyu,mbyd,MASKSIZE);

    Add128(&res1,&res2,myu[0],myd[0],myu[1], myd[1]);
    for (i = 2; i<MASKSIZE; i++){
        Add128(&res1,&res2,res1,res2,myu[i], myd[i]);
    }
    printf("res1 = %lu\n", res1);
    print_binary_form(res1);
    printf("res2 = %lu\n", res2);
    print_binary_form(res2);

    A2B128(p1,p2,mxu,mxd,MASKSIZE);

    UnmaskB(&res_m1, p1);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);
    UnmaskB(&res_m1, p2);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    return 0;
}
