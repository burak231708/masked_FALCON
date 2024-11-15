#include <stdio.h>

#include "utils.h"

int main(void){
    //declaration
    uint64_t res;
    uint64_t a128, b128, c128, d128;


    printf("-------------------------------test_random----------------------------------\n");
    printf("\n");
    
    res = rand64();
    printf("res = %lu\n", res);
    res = randmod(16);
    printf("res = %lu\n", res);

    print_binary_form(res);

    printf("-------------------------------test_op_128----------------------------------\n");
    printf("\n");

    a128 = -(1UL);//(1UL<<63);
    b128 = -(1UL);//(1UL<<63);
    Mult128(&c128, &d128, a128, b128);

    print_binary_form(a128);
    print_binary_form(b128);
    print_binary_form(c128);
    print_binary_form(d128);

    return 0;
}