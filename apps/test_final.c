#include <stdio.h>

#include <time.h>
#include <stdlib.h>

#include "secfpr.h"
#include "chenchen_gadgets.h"
#include "chenchen_modify.h"
#include "gadgets.h"
#include "utils.h"



int main(void){

    maskedb_t in1;
    maskedb_t in2;
    //maskedb_t in3;
    //maskeda_t ina1;
    maskedb_t out1;
    //uint64_t p;
    //maskedb_t out2;
    clock_t start;
    double max = 0;
    double res = -1;
    double moy = 0;
    size_t i, j;

    srand((unsigned int)time(NULL));


    for (j = 0; j<1000; j++){
        for(i = 0; i<10; i++){
            MaskB(in1, (rand64()%0x40C3880000000000));
            MaskB(in2, ((rand64()%2443951759977325) + 0x3FF47201BF2577E7));
            //MaskB(in3, (rand64()));
            //p = rand64() % 11;
            //MaskA(ina1, rand64(), 1<<16);
            start = clock();
            SamplerZ(out1, in1, in2);
            
            res = (double)((clock()-start));
            
            //printf("res = %f\n", res);
            if ((double)max<res) max = res;
            moy += res;
        } 

    }

    moy/=100;
    moy/=100;
    printf("moy = %f\n", moy);
    printf("max = %f\n", max);


    return 0;
}