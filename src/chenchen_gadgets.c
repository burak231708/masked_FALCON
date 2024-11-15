#include <stdio.h> //printf
#include <stdlib.h>
#include <time.h>

#include "gadgets.h"
#include "utils.h"
#include "chenchen_gadgets.h"


//Constants

#define SIZE              63U //64-1
#define HALF_SIZE         32U
#define HALF_BIT          4294967295U //eq. 0xffffffff 
#define RAND_GENERATOR_1  0xF108E4CD87654321UL 
#define RAND_GENERATOR_2  0x1525374657E5F50DUL
#define RAND_GENERATOR_3  0x8B459B95879A07F3UL 
#define ONE               1UL
#define THREE             3UL

static void vecRightRotate(maskedb_t in, uint64_t c);

/*------------------------------------------------
SecOr     :   Secure OR at order MASKORDER
input     :   Boolean maskings ina,inb (maskedb_t)
output    :   Boolean masking out (maskedb_t)
------------------------------------------------*/
void SecOr(maskedb_t out, maskedb_t ina, maskedb_t inb)
{
    uint64_t t[MASKSIZE],s[MASKSIZE];
    size_t i;
    t[0] = ~ina[0];
    s[0] = ~inb[0];
    for(i = 1; i< MASKSIZE; i++){
        t[i] = ina[i];
        s[i] = inb[i];
    }
    SecAnd(out,t,s, MASKSIZE);
    out[0] = ~out[0];
}

/*------------------------------------------------
SecNonZeroB :   Secure check that remaining bits are
                non zero (input boolean) at 
                order MASKORDER
input       :   Boolean masking in (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/
void SecNonZeroB(maskedb_t out, maskedb_t in){
    uint64_t t[MASKSIZE],l[MASKSIZE],r[MASKSIZE],t2[MASKSIZE];
    size_t i;
    uint64_t len = 32;
    uint64_t mask;
    for(i= 0; i < MASKSIZE; i++){
        t[i] = in[i];
    }
    while(len>=1){
        mask = 0;
        for (i = 0; i<(size_t)len; i++){
            mask += 1UL<<i;
        }
        for(i = 0; i<MASKSIZE;i++){
            t2[i] = (t[i]>>(len)) & mask;
        } 
        RefreshXOR(l,t2,(1UL<<len),MASKSIZE);
        for(i = 0; i<MASKSIZE; i++){
            r[i] = t[i] & mask;
        }
        SecOr(t,l,r);
        len = len >> 1;
    }
    for(i = 0; i <MASKSIZE; i++){
        out[i] = t[i]&1UL;
    } // (t_i^{(1)})
}


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
SecFprUrsh  :   Secure right-shift
input       :   Boolean masking in (maskedb_t)
                6-bits Integer vector c
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void SecFprUrsh(maskedb_t out, maskedb_t x, maskeda_t c){
    maskedb_t m;
    maskedb_t in;
    maskedb_t temp;
    maskedb_t b;
    size_t i, j;
    uint64_t len = 1;
    for (i = 0; i<MASKSIZE; i++){
        in[i] = x[i];
        m[i] = 0;
    }
    m[0] = 1UL<<63;
    for (j = 0; j< MASKSIZE; j++){
        vecRightRotate(in, c[j]);
        RefreshMasks(in, MASKSIZE);
        vecRightRotate(m, c[j]);
        RefreshMasks(m, MASKSIZE);
    }
    while(len<=32){
        for (i = 0; i < MASKSIZE; i++){
            m[i] = m[i] ^ (m[i]>>len);
        }
        len = len << 1;
    }
    SecAnd(temp, in, m,MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        out[i] = temp[i] ^ in[i];
        out[i]^= temp[i] & 1;
    }
    SecNonZeroB(b, out);
    for (i = 0; i<MASKSIZE; i++){
        out[i] = (temp[i] - (temp[i] & 1UL));
    }
}

/*------------------------------------------------
SecFprNorm64:   Secure right-shift
input       :   Boolean masking out (maskedb_t)
                Arithmetic masking e (maskeda_t)
                modulus mod (uint64_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void 
SecFprNorm64(maskedb_t out, maskeda_t e, uint64_t mod){
    maskedb_t t, n, b, bp;
    maskeda_t ba;
    size_t i, j;
    e[0]= e[0]-63;
    for (j = 6 ; j!=0; j--){
        for (i = 0; i < MASKSIZE; i++){
            t[i] = out[i] ^ (out[i]<<(1<<(j-1)));
            n[i] = out[i] >> (64 - (1<<(j-1)));
        }
        SecNonZeroB(b, n); 
        for (i = 0; i < MASKSIZE; i++){
            bp[i] = -b[i];
        }

        bp[0] = ~bp[0];
        SecAnd(t, t, bp, MASKSIZE);

        for (i = 0; i < MASKSIZE; i++){
            out[i] = out[i] ^ t[i];
        }
        B2A_bit(ba, b, mod);
        for (i = 0; i < MASKSIZE; i++){
            e[i] = e[i] + (ba[i]<<(j-1)) %mod;
        }
    }
}

void SecFpr(maskedb_t x, maskedb_t s, maskeda_t e, maskedb_t z){
    maskedb_t eb, b, za, f;
    size_t i;

    e[0] += 1076;
    A2B(eb, e, 1<<16);

    for (i = 0; i<MASKSIZE; i++){
        b[i] =  -((eb[i]>>15)&1);
    } 
    b[0] = ~b[0];
    SecAnd(z, z, b, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        b[i] =  -((z[i]>>54)&1);
    }
    SecAnd(eb,eb,b, MASKSIZE);
    SecAnd(s,s,b, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        b[i] =  ((z[i]>>54)&1);
    } 
    SecAdd(eb, eb, b, MASKSIZE);
    RefreshXOR_64(eb,eb,MASKSIZE);
    RefreshXOR_64(s,s,MASKSIZE);

    for (i = 0; i<MASKSIZE; i++){
        x[i] = (s[i]<<63) ^ ((eb[i])<<52) ^ ((z[i]>>2)& 0xfffffffffffff);
        b[i] =  ((z[i])&1);
        za[i] = ((z[i]>>2)&1);
    } 
    RefreshXOR_64(b,b,MASKSIZE);
    SecOr(f,b, za);
    for (i = 0; i<MASKSIZE; i++){
        za[i] =  ((z[i]>>1)&1);
    } 
    SecAnd(f, f, za, MASKSIZE);
    SecAdd(x,f,x,MASKSIZE);
}

/*------------------------------------------------
SecFprMul   :   Secure multiplication
input       :   Boolean masking x, y (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void SecFprMul(maskedb_t out, maskedb_t x, maskedb_t y){
    maskedb_t s,sbx,sby,p1,p2,b,z,z2,w,w2,bx,by,d,ebx,eby,mbxu,mbxd,mbyu,mbyd, b1,b2;
    maskeda_t e,eax,eay,wa,p3,p4,mxu,mxd,myu,myd;
    size_t i;

    //EXTRACTION
    for(i =0; i < MASKSIZE;i++){
        sbx[i] = (x[i]>>63);
        sby[i] = (y[i]>>63);
        ebx[i] = ((x[i]<<1)>>53);
        eby[i] = ((y[i]<<1)>>53);
        mbxd[i] = x[i] & 0xfffffffffffff;
        mbxu[i]=0;
        mbyd[i] = y[i] & 0xfffffffffffff;
        mbyu[i]=0;
    }
    SecNonZeroB(b1, x);
    SecNonZeroB(b2, y);
    for(i = 0; i<MASKSIZE; i++){
        mbxd[i] = mbxd[i] ^ (b1[i]<<52);
        mbyd[i] = mbyd[i] ^ (b2[i]<<52);
    }

    B2A(eax,ebx,(1<<16),MASKSIZE);
    B2A128(mxu,mxd,mbxu,mbxd,MASKSIZE);
    B2A(eay,eby,(1<<16),MASKSIZE);
    B2A128(myu,myd,mbyu,mbyd,MASKSIZE);
    
    for(i= 0; i <MASKSIZE; i++){
        s[i] = sbx[i]^sby[i];
        e[i] = eax[i] + eay[i];
    }
    e[0] = eax[0] + eay[0] -2100;
    
    SecMult128(p3,p4,mxu,mxd,myu,myd);
    A2B128(p1,p2,p3,p4,MASKSIZE);

    for (i = 0; i<MASKSIZE; i++){
        b[i] = (p2[i]<<(13))>>13;
        z[i] = p2[i]>>50;
        z2[i] = p2[i]>>51;
    }
    for (i = 0; i<MASKSIZE; i++){
        z[i]^= (p1[i]<<23)>>9;
        z2[i]^= (p1[i]<<22)>>9;
    }
    SecNonZeroB(b,b);
    
    for (i = 0; i<MASKSIZE; i++){
        z2[i] = z2[i]^z[i];
        w[i] = (p1[i]>>41)&1;
        w2[i] = -w[i];
    }
    RefreshXOR_64(w2, w2, MASKSIZE);
    SecAnd(z2, z2, w2, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        z[i] = z2[i]^z[i];
    }
    SecOr(z, z, b );
    B2A_bit(wa, w, 1<<16);

    for(i = 0; i<MASKSIZE; i++){ 
        e[i] = e[i] + wa[i];
    }

    SecNonZeroB(bx, ebx);
    SecNonZeroB(by, eby);

    SecAnd(d,bx,by, MASKSIZE);

    for (i = 0; i<MASKSIZE; i++){ 
        d[i] = -(d[i]&1);
    }
    SecAnd(z, z, d, MASKSIZE);
    SecFpr(out, s, e, z);
}

/*------------------------------------------------
SecFprAdd  :   Secure Addition
input       :   Boolean masking in1, in2 (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void SecFprAdd(maskedb_t out, maskedb_t in1, maskedb_t in2){
    size_t i, j;
    //Part 1
    maskedb_t in1temp, in2temp;
    maskedb_t in1m, in2m, d, b, bp, cs, m, x_63, dp;
    maskedb_t csp;
    //Part 2
    maskedb_t mx, my, sx, sy, exp, eyp;
    maskeda_t ex, ey;
    //Part 3
    maskeda_t c, temp, s;
    maskedb_t cp, myp, tempb, un, z;
    maskeda_t tempA;
    //Part 4
//PART 1 : SWAP PART
    for(i = 0; i<MASKSIZE; i++){
        in1temp[i]=in1[i];
        in2temp[i]=in2[i];
    }
    for (i = 0; i<MASKSIZE; i++){
        in1m[i] = (in1temp[i]<<1)>>1;
        in2m[i] = (in2temp[i]<<1)>>1;
    }
    in2m[0] = ~in2m[0];
    SecAdd(d, in1m, in2m, MASKSIZE);      //d=xm-ym-1
    for (i = 1; i<MASKSIZE; i++){
        dp[i] = d[i];
    }
    dp[0] = ~d[0];
    SecNonZeroB(b, dp);
    dp[0] = ~(d[0] ^ (1UL<<63));
    SecNonZeroB(bp,dp);
    for (i = 1; i<MASKSIZE; i++){
        dp[i] = b[i];
    }
    dp[0] = ~b[0];
    for (i = 0; i<MASKSIZE; i++){
        x_63[i] = in1[i]>>63;
    }
    SecAnd(cs, dp, x_63,MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        x_63[i] = (d[i]>>63) ^ b[i] ^ bp[i];
    }
    SecOr(cs, cs, x_63);
    for (i = 0; i<MASKSIZE; i++){
        x_63[i] = in1[i] ^ in2[i];
    }
    // OPERATION : -cs. when cs = 0 ----> cps = 0
    //                  when cs = 1 ----> cps = 0xff..ff
    for (j = 0; j<MASKSIZE; j++){
        csp[j] = 0;
        for (i = 0; i<64; i++){
            csp[j] ^= ((cs[j])<<i);
        }
    }
    RefreshMasks(csp,MASKSIZE);
    SecAnd(m, x_63, csp,MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        in1temp[i] = in1temp[i] ^ m[i];
        in2temp[i] = in2temp[i] ^ m[i];
    }
//PART 2 : EXTRACTING (S,E,M)
    for (i = 0; i<MASKSIZE; i++){
        //52 low bits. 
        mx[i] = (in1temp[i]<<12)>>12; //&0xffffffffffffff;
        my[i] = (in2temp[i]<<12)>>12;
        //11 bits just after the 52 first bits.
        exp[i] = (uint32_t)(in1temp[i]>>52);
        exp[i] = exp[i] - (exp[i]&2048); 
        eyp[i] = (uint32_t)(in2temp[i]>>52);
        eyp[i] = eyp[i] - (eyp[i]&2048);
        //1st/top bit.
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
    SecAdd(myp, myp, un, MASKSIZE);
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
    SecFprNorm64(z, ex, (1UL<<16));
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