#include <stdio.h>

#include "secfpr.h"
#include "fpr_gadgets.h"
#include "fpr_modify.h"
#include "gadgets.h"
#include "utils.h"



int main(void){
    uint64_t res1 = rand64();
    uint64_t res2 = rand64();
    uint64_t res_m1 = 0;
    maskedb_t m1, m2, m3, m4;
    uint64_t count_0, count_1;
    size_t i;
    int tab_count[15] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    int count_err = 0;

    printf("---------------------------------test_SECFPR---------------------------------\n");
    printf("\n");

    printf("Test SecFprScalPtwo(11) / SecFprDivScalTwo(11)\n");
    printf("m1    = %lu\n", res1);
    print_binary_form(res1);
    MaskB(m1, res1);
    printf("\nTest SecFprScalPtwo(11)\n");
    SecFprScalPtwo(m3, m1, 11);
    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    printf("\nTest SecFprDivScalTwo(11)\n");

    SecFprDivPtwo(m3, m1, 11);
    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    printf("\nTest Trunc / Floor\n");

    print_binary_form(0x4016000000000000);
    res1 = 0x4016000000000000;
    printf("m1    = %lu\n", res1);
    print_binary_form(res1);
    MaskB(m1, res1);
    UnmaskB(&res_m1, m1);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    printf("\nFloor :\n");
    SecFprFloor(m3, m1);
    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);



    printf("\nTest ApproxExp\n    x in [0; ln(2)[\n    c in [0; 1]\n");
    res1 = rand64()%0x3FE62E42FEFA3BDC; // 0x3FE62E42FEFA3BDC = ln(2)
    res2 = rand64()%0x3FF0000000000000; // 0x3FF0000000000000 = 1
    printf("m1    = %lu\n", res1);
    print_binary_form(res1);
    MaskB(m1, res1);
    printf("m2    = %lu\n", res2);
    print_binary_form(res2);
    MaskB(m2, res2);

    SecApproxExp(m3, m1, m2);

    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

    printf("\nTest ApproxExp\n    x = 0.5 \n    c = 0.5\nexpected result ~ 2797128963144291325 (decimal) ~= 0x43C368B2FC6F960A (double) or %lu\n", 0x43C368B2FC6F960A);
    print_binary_form(0x43C368B2FC6F960A);
    res1 = 0x3FE0000000000000; // 0x3FE62E42FEFA3BDC = ln(2)
    res2 = 0x3FE0000000000000; // 0x3FF0000000000000 = 1
    printf("m1    = %lu\n", res1);
    print_binary_form(res1);
    MaskB(m1, res1);
    printf("m2    = %lu\n", res2);
    print_binary_form(res2);
    MaskB(m2, res2);

    SecApproxExp(m3, m1, m2);

    UnmaskB(&res_m1, m3);
    printf("res_m = %lu\n", res_m1);
    print_binary_form(res_m1);

   

    count_0 = 0;
    count_1 = 0;
    for (i = 0; i< 1000; i++){
        res2 = rand64();
        MaskB(m4,res2);
        res_m1 = SecFprBerExp(m3, m1, m2, m4);
        if (res_m1 == 1){
            count_1 ++;
        }else{
            count_0 ++;
        }
    }

    printf("count_0 = %lu     and count_1 = %lu\n\n\n", count_0, count_1);

    printf("\n-------------SamplerZ--------------\n");

    m1[0]  = 4609884578576439705;
    m1[1] = 0;
    m1[2] = 0;

    m2[0]  = 4608533498688228556;
    m2[1] = 0;
    m2[2] = 0;

    for (i = 0; i<10000; i++){

        SamplerZ(m3, m1, m2);
        UnmaskB(&res_m1, m3);
        switch ( res_m1 ){
            case 13842939354630062080UL: //-7
                tab_count[0] ++;
                break;
            case 13841813454723219456UL: //-6
                tab_count[1] ++;
                break;
            case 13840687554816376832UL: //-5
                tab_count[2] ++;
                break;
            case 13839561654909534208UL: //-4
                tab_count[3] ++;
                break;
            case 13837309855095848960UL: //-3
                tab_count[4] ++;
                break;
            case 13835058055282163712UL: //-2
                tab_count[5] ++;
                break;
            case 13830554455654793216UL: //-1
                tab_count[6] ++;
                break;
            case 0UL:  //0
                tab_count[7] ++;
                break;
            case 4607182418800017408UL: //1
                tab_count[8] ++;
                break;
            case 4611686018427387904UL: //2
                tab_count[9] ++;
                break;
            case 4613937818241073152UL: //3
                tab_count[10] ++;
                break;
            case 4616189618054758400UL: //4
                tab_count[11] ++;
                break;    
            case 4617315517961601024UL: //5
                tab_count[12] ++;
                break;
            case 4618441417868443648UL: //6
                tab_count[13] ++;
                break;
            case 4619567317775286272UL: //7
                tab_count[14] ++;
                break;
            default:
                print_binary_form(res_m1);
                count_err ++;
        }
    }

    for (i = 0; i<15; i++){
        printf("tab_count[%li] = %i\n", i-7, tab_count[i]);
    }

    printf("tab_err = %i\n", count_err);

    return 0;
}
