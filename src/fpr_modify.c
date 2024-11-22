#include <stdio.h> //printf
#include <stdlib.h>
#include <time.h>

#include "gadgets.h"
#include "utils.h"
#include "fpr_gadgets.h"
#include "fpr_modify.h"

//Constants

#define SIZE              63U //64-1
#define HALF_SIZE         32U
#define HALF_BIT          4294967295U //eq. 0xffffffff 
#define ONE               1UL

static void vecRightRotate(maskedb_t in, uint64_t c);

static void vecRightRotate(maskedb_t in, uint64_t c){
    size_t i;
    uint64_t temp1, temp2;
    for (i = 0; i<MASKSIZE; i++){
        temp1 = (1UL << c) - 1;
        temp1 = in[i] & temp1;
        temp2 = ((in[i]) >> c);
        in[i] = (temp2) ^ (temp1 << (64UL - c));  
    } 
}


/*------------------------------------------------
SecFprUrsh3 :   Secure right-shift
input       :   Boolean masking in (maskedb_t)
                6-bits Integer vector c
output      :   Boolean masking out (maskedb_t)
                Boolean masking out2 (maskedb_t)
------------------------------------------------*/

void SecFprUrshFloor(maskedb_t out, maskedb_t out2, maskedb_t in, maskeda_t c){
    maskedb_t m, inp;
    uint64_t len = 1;
    size_t j, i;
    for (i = 0; i<MASKSIZE; i++) {
        m[i] = 0;
        inp[i] = in[i];
    }
    m[0] = ((uint64_t)1)<<63;
    for (j =0; j< MASKSIZE; j++){
        vecRightRotate(inp, c[j]);
        RefreshMasks(inp, MASKSIZE);
        vecRightRotate(m, c[j]);
        RefreshMasks(m, MASKSIZE);
    }
    while(len<=32){
        for (i = 0; i < MASKSIZE; i++){
            m[i] = m[i] ^ (m[i]>>len);
        }
        len = len << 1;
    }
    SecAnd(out, inp, m,MASKSIZE);
    RefreshMasks(m, MASKSIZE);
    for (i = 0; i < MASKSIZE; i++){
            m[i] = ~m[i];
    }
    SecAnd(out2, inp, m, MASKSIZE);
}

/*------------------------------------------------
SecFprUrshTrunc :   Secure right-shift without sticky bit
input       :   Boolean masking in (maskedb_t)
                6-bits Integer vector c
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void SecFprUrshTrunc(maskedb_t out, maskedb_t in, maskeda_t c){
    maskedb_t m, inp;
    size_t i, j;
    uint64_t len = 1;
    for (i = 0; i<MASKSIZE; i++) {
        m[i] = 0;
        inp[i] = in[i];
    }
    m[0] = (1UL)<<63;
    for (j =0; j< MASKSIZE; j++){
        vecRightRotate(inp, c[j]);
        RefreshMasks(inp, MASKSIZE);
        vecRightRotate(m, c[j]);
        RefreshMasks(m, MASKSIZE);
    }
    while(len<=32){
        for (i = 0; i < MASKSIZE; i++){
            m[i] = m[i] ^ (m[i]>>len);
        }
        len = len << 1;
    }
    SecAnd(out, inp, m,MASKSIZE);
}


/*------------------------------------------------
SecFprAdd3  :   Secure Addition for division
input       :   Boolean masking in1, in2 (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void SecFprAddDiv(maskedb_t out, maskedb_t in1, maskedb_t in2){
    size_t i;
    //Part 1 
    maskedb_t in1temp, in2temp, b;
    //Part 2
    maskedb_t mx, my, sx, sy, exp, eyp;
    maskeda_t ex, ey;
    //Part 3
    maskeda_t c, temp, s;
    maskedb_t cp, myp, tempb, un, z;
    maskeda_t tempA;

//PART 1 : SWAP PART
    for(i = 0; i<MASKSIZE; i++){
        in1temp[i]=in1[i];
        in2temp[i]=in2[i];
    }
//PART 2 : EXTRACTING (S,E,M)
    for (i = 0; i<MASKSIZE; i++){
        //52 low bits. 
        mx[i] = (in1temp[i]<<12)>>12; 
        my[i] = (in2temp[i]<<12)>>12;
        //11 bits just after the 52 first bits.
        exp[i] = (uint32_t)(in1temp[i]>>52);
        exp[i] = exp[i] - (exp[i]&2048); 
        eyp[i] = (uint32_t)(in2temp[i]>>52);
        eyp[i] = eyp[i] - (eyp[i]&2048);
        //1 top bit.
        sx[i] = in1temp[i]>>63;
        sy[i] = in2temp[i]>>63;
    }
//PART 3 : OPERATIONS ON (S,E,M)
    mx[0] += 1UL << 52;
    RefreshMasks(mx, MASKSIZE);
    my[0] += 1UL << 52;
    RefreshMasks(my, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        mx[i]<<=3;
        my[i]<<=3;
    }
    B2A(ex, exp, (1<<16), MASKSIZE);
    B2A(ey, eyp, (1<<16), MASKSIZE);
    ex[0] -=1078;
    ey[0] -=1078;
    for (i = 0; i < MASKSIZE; i++){
        c[i] = ex[i] - ey[i];
        temp[i] = c[i];
    }
    temp[0] -= 60;
    A2B(cp, temp, (1<<16));
    for (i = 0; i<MASKSIZE; i++){
        tempb[i] = -((cp[i]>>15)&1); 
    }
    SecAnd(my, my, tempb,MASKSIZE);
    for (i =0; i<MASKSIZE; i++){
        tempA[i] = c[i]& 63;
    } 
    SecFprUrsh(my, my, tempA);
    for (i = 1; i<MASKSIZE; i++) {
        myp[i] = my[i];
        un[i] = 0;
    }
    un[0] = 1;
    myp[0] = ~my[0];
    SecAdd(myp, myp, un,MASKSIZE);

    for (i = 0; i<MASKSIZE; i++){
        s[i] = (-(sx[i] ^ sy[i]));
    } 
    RefreshMasks(my, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        tempb[i] = my[i] ^ myp[i];
    } 
    SecAnd(myp, tempb, s,MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        my[i] = my[i] ^ myp[i];
    } 
    SecAdd(z, mx, my,MASKSIZE);
    SecFprNorm64(z,ex, 1<<16);
    for (i = 0; i<MASKSIZE; i++){
        b[i] = z[i]&1023;
    }
    SecNonZeroB(b,b);
    for (i = 0; i<MASKSIZE; i++) {
        z[i] = z[i]>>9;
        z[i] = z[i] - (z[i]&1) + b[i];
    }
    ex[0]+= 9;
    //PART 4 : SEC FPR
    SecFpr(out, sx, ex, z );

}

/*------------------------------------------------
SecFprComp  :   Secure comparison
input       :   Boolean masking in1, in2 (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void SecFprComp(maskedb_t out, maskedb_t in1, maskedb_t in2){
    /*If |in1| >= |in2| ----> return 0
    If |in1| < |in2| ----> return 1
    Compare only mantissa and exponant.
    */
    maskedb_t in1m, in2m, d, b, bp, dp;
    size_t i;
    RefreshXOR_64(in1, in1, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        in1m[i] = (in1[i]<<1)>>1;
        in2m[i] = (in2[i]<<1)>>1;
    }
    in2m[0] = ~in2m[0];
    SecAdd(d, in1m, in2m, MASKSIZE);      //d=xm-ym-1
    RefreshXOR_64(in2, in2, MASKSIZE);
    for (i = 1; i<MASKSIZE; i++){
        dp[i] = d[i];
    }
    dp[0] = ~d[0];
    SecNonZeroB(b, dp);
    dp[0] = ~(d[0] ^ (1UL<<63));
    SecNonZeroB(bp,dp);
    for (i = 0; i<MASKSIZE; i++){
        out[i] = (d[i]>>63) ^ b[i] ^ bp[i];
    }
}
