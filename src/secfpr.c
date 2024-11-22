#include <assert.h> //assert for debug
#include <stdio.h> //printf
#include <stdlib.h>
#include <time.h>

#include "gadgets.h"
#include "utils.h"
#include "fpr_modify.h"
#include "fpr_gadgets.h"


//Constants

#define SIZE              63U //64-1
#define HALF_SIZE         32U
#define ONE               1UL

/*------------------------------------------------
SecFprScalPtwo  :   Secure multiplication by a power of two
input           :   Boolean masking in1, in2 (maskedb_t)
                    Integer ptwo (uint16_t)
output          :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void SecFprScalPtwo(maskedb_t out, maskedb_t in1, uint16_t ptwo){
    maskedb_t mx, sx, exp, b;
    maskeda_t ex;
    size_t i;

    for (i = 0; i<MASKSIZE; i++){
        //52 low bits. 
        mx[i] = (in1[i]<<12)>>12; 
        //11 bits just after the 52 first bits.
        exp[i] = (uint32_t)(in1[i]>>52);
        exp[i] = exp[i] - (exp[i]&2048); 
        //1 top bit.
        sx[i] = in1[i]>>63;
    }
    SecNonZeroB(b, exp);
    for (i =0; i<MASKSIZE; i++){
        b[i] = -b[i];
    } 
    B2A(ex, exp, 1<<16, MASKSIZE);
    ex[0] += ptwo;
    A2B(exp, ex, 1<<16);
    SecAnd(exp, exp, b, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        out[i] = (mx[i]) ^ ((exp[i])<<52) ^ (sx[i]<<63);
    } 
    RefreshXOR_64(out, out, MASKSIZE);
}

/*------------------------------------------------
SecFprDivPtwo  :   Secure division by a power of two
input           :   Boolean masking in1, in2 (maskedb_t)
                    Integer ptwo (uint16_t)
output          :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void SecFprDivPtwo(maskedb_t out, maskedb_t in1, uint16_t ptwo){
    maskedb_t mx, sx, exp, b;
    maskeda_t ex;
    size_t i;

    for (i = 0; i<MASKSIZE; i++){
        //52 low bits. 
        mx[i] = (in1[i]<<12)>>12; 
        //11 bits just after the 52 first bits.
        exp[i] = (uint32_t)(in1[i]>>52);
        exp[i] = exp[i] - (exp[i]&2048); 
        //1 top bit.
        sx[i] = in1[i]>>63;
    }
    SecNonZeroB(b, exp);
    for (i =0; i<MASKSIZE; i++){
        b[i] = -b[i];
    } 
    B2A(ex, exp, 1<<16, MASKSIZE);
    ex[0] -= ptwo;
    A2B(exp, ex, 1<<16);
    SecAnd(exp, exp, b, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        out[i] = (mx[i]) ^ ((exp[i])<<52) ^ (sx[i]<<63);
    } 
    RefreshXOR_64(out, out, MASKSIZE);
}



/*------------------------------------------------
SecFprFloor :   Secure floor function
input       :   Boolean masking in (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void 
SecFprFloor(maskedb_t out, maskedb_t in){
    size_t i, j;
    //Part 1
    maskedb_t mx, sx, exp, c, c0, cp, cd;
    maskeda_t ex, cx;
    //Part 2
    maskedb_t mout, sout; 
    maskeda_t eout; 
    //Part 3 
    maskedb_t cc;
    maskedb_t cs;
    //Part 4 
    maskedb_t Int_test;
    maskedb_t b;
    //Part 5
    maskedb_t eoutp; 
    maskedb_t bd;
//PART 1 : Extract mx, ex, sx
    for (i = 0; i<MASKSIZE; i++){
        //52 low bits. 
        mx[i] = (in[i]<<12)>>12; 
        //11 bits just after the 52 first bits.
        exp[i] = (uint32_t)(in[i]>>52);
        exp[i] = exp[i] - (exp[i]&2048); 
        //1 top bit.
        sx[i] = in[i]>>63;
    }
    mx[0] += 1UL << 52;
    RefreshMasks(mx, MASKSIZE);
    B2A(ex, exp, (1<<16), MASKSIZE);
//PART 2 : Check if e-1023 is positive or not
    for(i = 0; i<MASKSIZE; i++){
        cx[i] = ex[i];
    } 
    cx[0] = ex[0] - 1023;
    RefreshXOR_64(ex, ex, MASKSIZE);
    RefreshXOR_64(sx, sx, MASKSIZE);
    A2B(c, cx, 1<<16);
    for(i = 0; i<MASKSIZE; i++){
        c[i] = (c[i]>>15)&1;
    }
    for (j = 0; j<MASKSIZE; j++){
        c0[j] = -c[j];
    }
    c0[0] = ~c0[0];
    SecAnd(mout, c0, mx, MASKSIZE); 
    for (i = 0; i<MASKSIZE; i++) eout[i] = exp[i];
    for (i = 0; i<MASKSIZE; i++) sout[i] = sx[i];
//PART 3 : Check if e-1023 is superior than 52
    cx[0] = cx[0] - 52;
    A2B(c, cx, 1<<16);
    for(i = 0; i<MASKSIZE; i++) cc[i] = (c[i]>>15)&1;
    for (j = 0; j<MASKSIZE; j++){
        cp[j] = -cc[j];
        cs[j] = cc[j]; 
    }
    SecAnd(c, c, cp, MASKSIZE);
    B2A(cx, c, 1<<16, MASKSIZE);
//PART 4 : SecFprUrsh
    for (i = 0; i<MASKSIZE; i++){
        cd[i] = (-(cx[i]));
    } 
    SecFprUrshFloor(mout,Int_test, mout, cd);
    SecNonZeroB(b, Int_test);
    SecAnd(cs, b, sout, MASKSIZE);
    SecAdd(mout, mout, cs,  MASKSIZE);
    for (i = 0; i<MASKSIZE; i++) eout[i] += cd[i];
//PART 5 : Normalization
    SecFprNorm64(mout, eout, 1<<16);
    for (i = 0; i<MASKSIZE; i++){
        mout[i] = mout[i]>>11;
    }
    eout[0] = eout[0] +11;
    A2B(eoutp, eout, 1<<16);
    SecNonZeroB(bd,sout);
    for (i = 0; i<MASKSIZE; i++){
        bd[i] = -bd[i];
    } 

    SecOr(bd, bd, c0);
    SecAnd(eoutp,eoutp, bd, MASKSIZE);
    SecAnd(sout, sout, bd, MASKSIZE);

    for (i = 0; i<MASKSIZE; i++){
        out[i] = ((mout[i]<<12)>>12) + (eoutp[i]<<52) + (sout[i]<<63);
    } 

}


/*------------------------------------------------
SecFprInv   :   Secure inversion
input       :   Boolean masking in (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void SecFprInv(maskedb_t out, maskedb_t in){

    maskedb_t incpy,minus_in, comp,compp, one, eoneb, einb, min, b, sout, mout;
    maskeda_t ein;
    maskeda_t eone, eout, eoutb, ba; 
    maskedb_t  ma, f;
    size_t i, j;
    for(i = 0; i<MASKSIZE; i++){
        min[i] = (in[i]<<12)>>12; 
        einb[i] = (in[i]>>52);
        einb[i] = einb[i] - (einb[i]&2048);
        mout[i] = 0;
    }
    SecNonZeroB(b, min);
    B2A(ein, einb, 1<<16,MASKSIZE);
    ein[0] -= 1023;
    B2A(ba, b, 1<<16, MASKSIZE);
    MaskA(eone, 1023, 1<<16);
    for(i = 0; i<MASKSIZE; i++){
        eout[i] = eone[i] - ein[i]- ba[i];
        eone[i] += ein[i] + ba[i];
    } 
    A2B(eoneb, eone, 1<<16);
    A2B(eoutb, eout, 1<<16);

    for (i = 0; i<MASKSIZE; i++){
        one[i] = (eoneb[i]<<52);
    } 
    for (i = 0; i<MASKSIZE; i++){
        sout[i] = in[i]>>63;
    } 
    for (i = 0; i<MASKSIZE; i++){
        minus_in[i] = (in[i]<<1)>>1;
    } 
    minus_in[0] ^= (1UL<<63) ;

    SecFprComp(comp, in, one);
    for(j = 0; j<MASKSIZE; j++){
        mout[j] = ((comp[j]&1)<<(63));
    } 
    for (j = 0; j<MASKSIZE; j++){
        comp[j] = -comp[j];
    } 
    SecAnd(incpy, minus_in, comp, MASKSIZE);
    SecFprAdd(one, incpy, one);
    SecFprScalPtwo(one,one,1);

    for (i = 1; i<55; i++){
        SecFprComp(comp, in, one);
        for(j = 0; j<MASKSIZE; j++){
            compp[j] = ((comp[j]&1)<<(63-i));
        } 
        SecOr(mout, mout, compp);
        for (j = 0; j<MASKSIZE; j++){
            comp[j] = -comp[j];
        } 
        SecAnd(incpy, minus_in, comp, MASKSIZE);
        SecFprAdd(one, incpy, one);
        SecFprScalPtwo(one,one,1);
    }
    for (i = 0; i<MASKSIZE; i++){
        b[i] = -b[i];
        mout[i]>>=9;
    } 
    SecAnd(mout, mout, b, MASKSIZE);

    for (i = 0; i<MASKSIZE; i++){
        out[i] = (sout[i]<<63) ^ ((eoutb[i])<<52) ^ ((mout[i]>>2)& 0xfffffffffffff);
    } 

    
    for (i = 0; i<MASKSIZE; i++){
        b[i] =  ((mout[i])&1);
    }

    for (i = 0; i<MASKSIZE; i++){
        ma[i] =  ((mout[i]>>2)&1);
    }

    RefreshXOR_64(b,b,MASKSIZE);
    SecOr(f,b, ma);

    for (i = 0; i<MASKSIZE; i++){
        ma[i] =  ((mout[i]>>1)&1);
    } 
    SecAnd(f, f, ma, MASKSIZE);
   
    SecAdd(out,f,out,MASKSIZE);
}


/*------------------------------------------------
SecFprTrunc :   Secure truncature
input       :   Boolean masking in (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void 
SecFprTrunc(maskedb_t out, maskedb_t in){
    size_t i, j;
    //Part 1
    maskedb_t mx, sx, exp, c, c0, cp, cd;
    maskeda_t ex, cx;
    //Part 2
    maskedb_t mout, sout; 
    maskeda_t eout; 
    maskedb_t eoutp; 
//PART 1 : Extract mx, ex, sx
    for (i = 0; i<MASKSIZE; i++){
        //52 low bits. 
        mx[i] = (in[i]<<12)>>12; 
        //11 bits just after the 52 first bits.
        exp[i] = (uint32_t)(in[i]>>52);
        exp[i] = exp[i] - (exp[i]&2048); 
        //1 top bit.
        sx[i] = in[i]>>63;
    }
    mx[0] += 1UL << 52;
    RefreshMasks(mx, MASKSIZE);
    B2A(ex, exp, (1<<16), MASKSIZE);
//PART 2 : Check if e-1023 is positive or not
    for(i = 0; i<MASKSIZE; i++){
        cx[i] = ex[i];
    } 
    cx[0] = ex[0] - 1023;
    A2B(c, cx, 1<<16);
    for(i = 0; i<MASKSIZE; i++){
        c[i] = (c[i]>>15)&1;
    }

    for (j = 0; j<MASKSIZE; j++){
        c0[j] = 0;
        for (i = 0; i<64; i++){
            c0[j] ^= ((c[j])<<i);
        }
        c0[j] = ~c0[j];
    }
    RefreshMasks(c0,MASKSIZE);

    SecAnd(mout, c0, mx, MASKSIZE); 
    for (i = 0; i<MASKSIZE; i++){
        eout[i] = ex[i];
    } 
    for (i = 0; i<MASKSIZE; i++){
        sout[i] = sx[i];
    }
//PART 3 : Check if e-1023 is superior than 52
    cx[0] = cx[0] - 52;
    A2B(c, cx, 1<<16);
    for(i = 0; i<MASKSIZE; i++){
        c[i] = (c[i]>>15)&1;
    } 
    for (j = 0; j<MASKSIZE; j++){
        cp[j] = 0;
        for (int i = 0; i<64; i++){
            cp[j] ^= ((c[j])<<i);
        }
    }
    RefreshMasks(cp,MASKSIZE);
    cx[0] = cx[0] + 52;
    A2B(c, cx, 1<<16);
    SecAnd(c, c, cp, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        c[i] = (c[i]);
    } 
    B2A(cx, c, 1<<16, MASKSIZE);
//PART 4 : SecFprUrsh
    cx[0] = cx[0] - 52 ;
    for (i = 0; i<MASKSIZE; i++){
        cd[i] = (-(cx[i]));
    }
    A2B(c, cd, 1<<16);
    SecAnd(c, c, cp, MASKSIZE);
    B2A(cd, c, 1<<16, MASKSIZE);
    SecFprUrshTrunc(mout, mout, cd);
    for (i = 0; i<MASKSIZE; i++){
        eout[i] += cd[i];
    }
//PART 5 : Normalization
    SecFprNorm64(mout, eout, 1<<16);
    for (i = 0; i<MASKSIZE; i++){
        mout[i] = mout[i]>>11;
    }
    eout[0] = eout[0] +11;
    A2B(eoutp, eout, 1<<16);
    SecAnd(eoutp,eoutp, c0, MASKSIZE);
    SecAnd(sout, sout, c0, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        out[i] = ((mout[i]<<12)>>12) + (eoutp[i]<<52) + (sout[i]<<63);
    }
}




/*------------------------------------------------
SecApproxExp:   Secure ApproxExp -> exp(-x)*ccs*2^{63}
input       :   Boolean masking x, ccs (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void
SecApproxExp(maskedb_t out, maskedb_t x, maskedb_t ccs)
{
    size_t u, i;
    maskedb_t z, yz, ymask, cmask;
    uint64_t Cp[] = {
		0x4211D0460E8C0000u,
		0x424B2A467E030000u,
		0x42827EE5F8A05000u,
		0x42B71D939DE04500u,
		0x42EA019EB1EDF080u,
		0x431A01A073DE5B8Cu,
		0x4346C16C182D87F5u,
		0x4371111110E066FDu,
		0x4395555555541C3Cu,
		0x43B55555555581FFu,
		0x43D00000000000ADu,
		0x43DFFFFFFFFFFFD2u,
		0x43E0000000000000u
	};

    

    for (i = 0; i<MASKSIZE; i++) ymask[i] = 0;
    ymask[0] = Cp[0];

    SecFprScalPtwo(z, x, 63);
    SecFprTrunc(z, z);

    for (u = 1; u < 13; u ++) {
        SecFprMul(yz, z, ymask);
        SecFprDivPtwo(yz, yz, 63);

        for (i = 0; i<MASKSIZE; i++) cmask[i] = 0;
        cmask[0] = Cp[u];
        yz[0] = yz[0] ^ (1UL<<63);

        SecFprAdd(ymask,yz,cmask);
	}

    SecFprScalPtwo(z, ccs, 63);
    SecFprTrunc(z,z);
    SecFprMul(ymask, ymask, z);
    SecFprDivPtwo(out, ymask, 63);
}


/*------------------------------------------------
SecFprBerExp:   Secure BerExp, retourne 1 avec proba exp(-x) * ccs
input       :   Boolean masking x, ccs (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

uint64_t
SecFprBerExp(maskedb_t out, maskedb_t x, maskedb_t ccs, maskedb_t alea){
    uint64_t fpr_ln2_inv = 0x3FF71547652B82FE;
    uint64_t fpr_ln2 = 0x3FE62E42FEFA39EF;
    maskedb_t inv_ln2, ln2, s, r, b, es, esa, z;
    maskedb_t stest;
    maskedb_t news, one;
    maskedb_t temp1, temp2, wb, b1;
    size_t i;
    maskeda_t cs;
    maskedb_t mz;
    uint64_t counter = 64;
    uint64_t counter2 = 64;
    uint64_t w = 0;
    uint64_t res;

    MaskB(inv_ln2, fpr_ln2_inv);
    MaskB(ln2, fpr_ln2);
    SecFprMul(s, inv_ln2, x);
    SecFprFloor(s,s);
    SecNonZeroB(stest,s);
    SecFprMul(r,ln2,s);
    SecNonZeroB(b, r);
    for (i = 0; i<MASKSIZE; i++){ 
        r[i] = r[i]^(b[i]<<63);
    }
    SecFprAdd(r,x,r);
    for (i = 0; i<MASKSIZE; i++){
        es[i] = ((s[i]<<1)>>53);
    } 
    B2A(esa, es, 1<<16, MASKSIZE);
    esa[0] -= 1029;
    A2B(es,esa, 1<<16);

    for (i = 0; i<MASKSIZE; i++){ 
        b[i] = -((es[i]>>15)&1);
    }
    SecAnd(s, b, s, MASKSIZE);
    MaskB(news, 0x404F800000000000);
    b[0] = ~b[0];
    SecAnd(news, news, b, MASKSIZE);
    SecAdd(s, s, news, MASKSIZE);
    SecApproxExp(z, r, ccs);
    MaskB(one, 0xBFF0000000000000); 
    SecFprScalPtwo(z, z, 1);
    SecFprAdd(z,z,one);
    esa[0] -= 46;
    for (i = 0; i<MASKSIZE; i++){ 
        cs[i] = -(esa[i]);
    }
    for (i = 0; i<MASKSIZE; i++) {
        s[i] = ((s[i]&((0xfffffffffffffUL)))+ (stest[i]<<52));
    }
    SecFprUrshTrunc(s, s, cs);
    B2A(cs, s, 1<<16, MASKSIZE);

    for(i = 0; i<MASKSIZE; i++){
        mz[i] = (z[i]<<12)>>12;
    }
    mz[0] += 1UL << 52;
 
    for (i = 0; i<MASKSIZE; i++) {
        mz[i] <<= 10;
    }
    SecFprUrshTrunc(mz, mz, cs);

    UnmaskB(&res, mz);

    do{
        counter -= 8;
        for (i = 0; i<MASKSIZE; i++){
            temp1[i] = ((mz[i]>>counter)&0xff);
        } 
        temp1[0] = -temp1[0];

        for (i = 0; i<MASKSIZE; i++){
            temp2[i] = (alea[i]>>counter2)&0xff;
        }
       
        SecAdd(wb, temp1, temp2, MASKSIZE);

        SecNonZeroB(b1,wb);
        UnmaskB(&w,b1);

    }while(((w==0)&(counter>0)));

    for(i = 0; i<MASKSIZE; i++){
        wb[i] = wb[i]>>63;
    }
    SecNonZeroB(out, wb);
    UnmaskB(&res, out);
    return (res);
}

/*------------------------------------------------
BaseSampler :   
input       :   Boolean masking x, ccs (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void 
BaseSampler(maskedb_t out)
{
    uint64_t rcdt[19][2];
    uint64_t u0, u1;
    uint64_t b;
    size_t i;
    uint64_t z0 = 0;
    uint64_t temp;
    uint64_t result[19] = {
        0x0000000000000000, //0
        0x3FF0000000000000, //1
        0x4000000000000000, //2
        0x4008000000000000, //3
        0x4010000000000000, //4
        0x4014000000000000, //5
        0x4018000000000000, //6
        0x401C000000000000, //7
        0x4020000000000000, //8
        0x4022000000000000, //9
        0x4024000000000000, //10
        0x4026000000000000, //11
        0x4028000000000000, //12
        0x402A000000000000, //13
        0x402C000000000000, //14
        0x402E000000000000, //15
        0x4030000000000000, //16
        0x4031000000000000, //17
        0x4032000000000000};//18

    rcdt[0][0] = 0xA3F;
    rcdt[0][1] = 0x7F42ED3AC380000;
    rcdt[1][0] = 0x54D;
    rcdt[1][1] = 0x32B181F3F7C0000; 
    rcdt[2][0] = 0x227;
    rcdt[2][1] = 0xdcdd093482a0000; 
    rcdt[3][0] = 0xad;
    rcdt[3][1] = 0x1754377c7998000; 
    rcdt[4][0] = 0x29;
    rcdt[4][1] = 0x5846caef33f2000; 
    rcdt[5][0] = 0x7;
    rcdt[5][1] = 0x74ac754ed74bc00; 
    rcdt[6][0] = 0x1;
    rcdt[6][1] = 0x024dd542b776b00; 
    for (i = 7; i<19; i++){
        rcdt[i][0] = 0;
    }
    rcdt[7][1] = 117656387352093658; 
    rcdt[8][1] = 8867391802663976; 
    rcdt[9][1] = 496969357462633; 
    rcdt[10][1] =  20680885154299; 
    rcdt[11][1] = 638331848991; 
    rcdt[12][1] = 14602316184; 
    rcdt[13][1] = 247426747; 
    rcdt[14][1] = 3104126; 
    rcdt[15][1] = 28824; 
    rcdt[16][1] = 198; 
    rcdt[17][1] = 1; 
    rcdt[18][1] = 0; 

    u0 = 0;
    u1 = 0;
    for (i = 0; i<72; i++){
        b = rand64()%2;
        if (i<60) {
        u1 += b<< i;
        }else{
        u0 ^= b<<(i-60);
        }
    } 
    
    for (int i = 0; i<18; i++){
        
        if ((u0<rcdt[i][0]) || ((u1<rcdt[i][1]) & (u0==rcdt[i][0]))){
        temp = 1;
        }else{
        temp=0;
        }
        z0 += temp; 
    }

    MaskB(out, result[z0]);
}

/*------------------------------------------------
SamplerZ    :   Secure SamplerZ
input       :   Boolean masking mu, sig (maskedb_t)
output      :   Boolean masking out (maskedb_t)
------------------------------------------------*/

void SamplerZ(maskedb_t out, maskedb_t mu, maskedb_t sig){
    //sigmin = 1.277833697 for FALCON 512
    //sigmin = 1.298280334 for FALCON 1024
    //sigmax = 1.8205 for FALCON 512 et 1024
    maskedb_t sigmax, i_sigmax, sigmin,r, r2,ccs, z0, minus_one, b, z, bp, x, i_sig, temp;
    maskedb_t alea;
    size_t i;

    MaskB(sigmax  , 0x3FFD20C49BA5E354);
    MaskB(i_sigmax, 0x3FC34F8BC183BBC2); 

    MaskB(sigmin, 0x3FF47201BF2577E7);   //Falcon512
    //MaskB(sigmin, 0x3FF4C5C199791E8B); //Falcon1024

    MaskB(minus_one, 0xBFF0000000000000);
    SecFprFloor(r2, mu);
    r2[0] ^= (1UL<<63); 
    SecFprAdd(r, mu, r2); 
    SecFprInv(i_sig, sig);
    SecFprMul(ccs, i_sig, sigmin);
    while(1){
        BaseSampler(z0);
        MaskB(bp, (rand64()));
        MaskB(b,0x3FF0000000000000);
        for(i = 0; i<MASKSIZE; i++){
            bp[i] = -(bp[i]&1);
        }
        SecAnd(b, b,bp, MASKSIZE);
        SecFprScalPtwo(z,b,1);
        SecFprAdd(z, minus_one, z);
        SecFprMul(z,z,z0);
        SecFprAdd(z,z,b);

        r[0] ^= (1UL<<63);
        SecFprAdd(x, z, r);
        SecFprMul(x,x,x);
        SecFprDivPtwo(x,x,1);
        SecFprMul(x,x,i_sig);
        SecFprMul(x,x,i_sig);

        SecFprMul(temp, z0, z0);
        SecFprMul(temp, temp, i_sigmax);
        temp[0] ^= (1UL<<63);

        SecFprAdd(x,x,temp);
        MaskB(alea, rand64());

        if(SecFprBerExp(temp,x,ccs, alea)){
            r2[0] ^= (1UL<<63); 
            SecFprAdd(out, z, r2);
            return;
        }
        
    }
}
