#include <stdio.h> //printf
#include <stdlib.h>
#include <time.h>


#include "gadgets.h"
#include "utils.h"


//Constants

#define SIZE              63U //64-1
#define HALF_SIZE         32U
#define ONE               1UL


//static void RefreshMasks(maskedb_t out, size_t size);
static uint64_t Psi(uint64_t x,uint64_t y);
static uint64_t Psi0(uint64_t x, uint64_t y,int n);
static void B2Aext(uint64_t *out, uint64_t *extended, uint64_t mod, size_t size);

static void A2B_rec(uint64_t *out, uint64_t *in, uint64_t mod, size_t size);
static void B2A_bit_j(maskeda_t C, maskeda_t A, uint64_t xn, uint64_t mod, size_t n);

static void Psi128(uint64_t *outup,uint64_t *outdown, uint64_t xu,uint64_t xd,uint64_t yu, uint64_t yd);
static void Psi0128(uint64_t *outup, uint64_t *outdown,uint64_t xu,uint64_t xd, uint64_t yu, uint64_t yd,size_t n);

static void B2Aext128(maskeda_t outup,maskeda_t outdown, maskedb_t extendedup, maskedb_t extendeddown, size_t size);


//----------------------------------------------------------------------------------------
/*------------------------------------------------
MaskB   :   Boolean Masking at order MASKORDER
input   :   sensitive data in (uint64_t)
output  :   Boolean masking out (maskedb_t)
------------------------------------------------*/
void MaskB(maskedb_t a_out, uint64_t ui64_in){
    uint64_t ui64_r = 0;
    size_t i;
    for(i = 0; (i < MASKORDER); i++){
        a_out[i] = rand64();
        ui64_r ^= a_out[i];
    }
    a_out[MASKORDER] = ui64_in ^ ui64_r;
}

/*------------------------------------------------
UnmaskB   :   Boolean unmasking at order MASKORDER
input     :   Boolean masking in (maskedb_t)
              Number of shares size (int)
output    :   sensitive data out (uint64_t)
------------------------------------------------*/
void UnmaskB(uint64_t * p_out, maskedb_t a_in){
    uint64_t ui64_r = 0;
    size_t i;
    for(i = 0; (i < MASKSIZE - 1); i++){
        ui64_r ^= a_in[i];
    }
    *p_out = a_in[MASKSIZE-1] ^ ui64_r;
}
//----------------------------------------------------------------------------------------
/*------------------------------------------------
SecAnd    :   Secure AND at order MASKORDER
input     :   Boolean maskings ina, inb (maskedb_t)
              Number of shares size (int)
output    :   Boolean masking out (maskedb_t)
------------------------------------------------*/
void SecAnd(maskedb_t out, maskedb_t ina, maskedb_t inb, size_t size)
{
    maskedb_t tempout;
    size_t i;
    uint64_t r[MASKSIZE][MASKSIZE];
    for(i = 0; i<size; i++){
        tempout[i] = ina[i]&inb[i];
    }
    for(i = 0; i <size-1; i++){
        for(size_t j = i+1; j< size;j++){
            r[i][j] = rand64();
            r[j][i] = (r[i][j]^(ina[i]&inb[j]));
            r[j][i] ^= (ina[j]&inb[i]);
            tempout[i] ^= r[i][j];
            tempout[j] ^= r[j][i];
        }
    }
    for(i = 0; i<size; i++) {
        out[i] = tempout[i];
    }
}

/*------------------------------------------------
RefreshXOR:   XOR with Refresh for SecAdd at order MASKORDER
input     :   Boolean masking in (maskedb_t), 
              Modulo k2 (uint64_t),
              Size size(int)
output    :   Boolean masking out (maskedb_t)
IMPORTANT NOTE
    To refresh all 64 bits, use k2 = 0
------------------------------------------------*/
void RefreshXOR(maskedb_t out, maskedb_t in, uint64_t k2, size_t size){
    uint64_t r;
    size_t i, j;
    for(i = 0; i<size; i++){
        out[i] = in[i];
    } 
    for(i = 0; i<size-1; i++){
        for(j = i+1; j<size; j++){
            r = randmod(k2);
            out[i] ^= r;
            out[j] ^= r;
        }
    }
}

void RefreshXOR_64(maskedb_t out, maskedb_t in, size_t size){
    uint64_t r;
    for(size_t i = 0; i<size; i++) out[i] = in[i];
    for(size_t i = 0; i<size-1; i++){
        for(size_t j = i+1; j<size; j++){
            r = rand64();
            out[i] ^= r;
            out[j] ^= r;
        }
    }
}

/*------------------------------------------------
RefreshMasks :   NI-Refresh at order MASKORDER
input        :   Boolean masking out (maskedb_t),
                 Amount of shares refreshed size (int)
output       :   Boolean masking out (maskedb_t)
------------------------------------------------*/
void RefreshMasks(maskedb_t out, size_t size){
    uint64_t r;
    size_t i;
    for(i = 1; i < size; i++){
        r = rand64();
        out[0] ^= r;
        out[i] ^= r;
    }
}


/*------------------------------------------------
SecAdd    :   Secure addition at order MASKORDER
input     :   Boolean maskings ina,inb (maskedb_t),
              Power of 2 k (uint64_t),
              Log2 of k minus 1 log2km1 (uint64_t)
              Number of shares size (int)
output    :   Arithmetic masking out (maskedb_t)
------------------------------------------------*/
void SecAdd(uint64_t *out, uint64_t *ina, uint64_t* inb, size_t size){
    uint64_t p[MASKSIZE],g[MASKSIZE],a[MASKSIZE],a2[MASKSIZE];
    size_t i, j;
    int pow=1;
    size_t log2km1 = 8;
    for(i = 0; i<size; i++) 
        p[i] = ina[i] ^ inb[i];
    SecAnd(g,ina,inb,size);
    for(j = 0; j<log2km1-1; j++){
        for(i = 0; i<size; i++) 
            a[i] = g[i] << pow;
        SecAnd(a2,a,p,size);
        for(i =0; i<size; i++) {
            g[i] ^= a2[i];
            a2[i] = p[i] << pow;
        }
        RefreshXOR_64(a2,a2,size);
        SecAnd(a,p,a2,size);
        for(i = 0; i < size; i++) p[i] = a[i];
        pow *= 2;
    }
    for(i = 0; i<size; i++) a[i] = g[i] << pow;
    SecAnd(a2,a,p,size);
    for(i = 0; i<size; i++){
        g[i] ^= a2[i];
        out[i] = ina[i]^inb[i]^(g[i]<<1);
    }
}


/*------------------------------------------------
MaskA   :   Arithmetic Masking at order MASKORDER
input   :   sensitive data in (uint64_t), Modulo mod (uint64_t)
output  :   Arithmetic masking out (maskeda_t)
------------------------------------------------*/
void MaskA(maskeda_t out, uint64_t in, uint64_t mod){
    uint64_t r = 0;
    size_t i = 0;
    for(i = 0; i < MASKORDER; i++){
        out[i] = randmod(mod);
        r = (r + out[i]) % mod;
    }
    out[MASKORDER] = subq(in,r,mod);
}

/*------------------------------------------------
UnmaskA   :   Arithmetic unmasking at order MASKORDER
input     :   Arithmetic masking in (maskeda_t), Modulo mod (uint64_t)
output    :   sensitive data out (uint64_t)
------------------------------------------------*/
void UnmaskA(uint64_t *out, maskeda_t in, uint64_t mod){
    uint64_t r = 0;
    size_t i;
    for(i = 0; i < MASKORDER; i++){
        r = (r + in[i]) % mod;
    }
    *out = (in[MASKORDER] + r) % mod;
}


/*------------------------------------------------
SecMult   :   Secure multiplication mod a power of 2 at order MASKORDER
input     :   Arithmetic maskings ina,inb (maskeda_t), Modulo mod (uint64_t)
output    :   Arithmetic masking out (maskeda_t)
------------------------------------------------*/
void SecMult(maskeda_t out, maskeda_t ina, maskeda_t inb, uint64_t mod){
    uint64_t r;
    size_t i, j;
    uint64_t temp = 0;
    for(i = 0; i < MASKSIZE; i++) {
        out[i] = (ina[i] * inb[i]) % mod;
    }
    for(i = 0; i < MASKSIZE-1; i++){
        for(j = i+1; j<MASKSIZE;j++){
            r = rand64() % mod;
            out[i] = out[i] - r;
            temp = (ina[i] * inb[j])% mod;
            r = r + temp;
            temp = (ina[j] * inb[i])% mod;
            r = r + temp;
            out[j] = (out[j] + r) % mod;
        }
    }
}



static void A2B_rec(uint64_t *out, uint64_t *in, uint64_t mod, size_t size){
    size_t i;
    uint64_t up[MASKSIZE],down[MASKSIZE];
    uint64_t y[MASKSIZE],z[MASKSIZE];
    if(size==1){
        out[0] = in[0];
        return;
    }
    else{
    

    for(i = 0; i < size/2; i++){
        down[i] = in[i];
    }
    for(i = 0; i < size-size/2; i++){ 
        up[i] = in[i+size/2];
    }

    A2B_rec(y,down,mod,size/2);
    A2B_rec(z,up,mod,size-size/2);

    for(i = size/2; i<size;i++){
        y[i] = 0;
    }
    for(i = size-size/2;i<size;i++){
        z[i] = 0;
    }

    RefreshXOR(y,y,mod,size);
    RefreshXOR(z,z,mod,size);
    SecAdd(out,z,y,size);
    }
}

void A2B(maskedb_t out, maskeda_t in, uint64_t mod){
    size_t i = 0;
    A2B_rec(out, in, mod, MASKSIZE);
    for (i = 0; i<MASKSIZE; i++){
        out[i] = out[i] % mod;
    }
}

//For B2A
static uint64_t Psi(uint64_t x,uint64_t y)
{
  return (x ^ y)-y;
}

//For B2A
static uint64_t Psi0(uint64_t x, uint64_t y,int n)
{
  return Psi(x,y) ^ ((~n & 1) * x);
}

static void B2Aext(uint64_t *out, uint64_t *x, uint64_t mod, size_t size){
    uint64_t r1, r2, y0, y1, y2, z0, z1;
    uint64_t y[MASKSIZE+1];
    uint64_t z[MASKSIZE];
    size_t i;
    uint64_t A[MASKSIZE];
    uint64_t B[MASKSIZE];
    if(size==2){
        r1 = rand64();
        r2 = rand64();

        y0 = (x[0]^r1)^r2;
        y1 = x[1]^r1;
        y2 = x[2]^r2;

        z0 = y0^Psi(y0,y1);
        z1 = Psi(y0,y2);

        out[0] = y1^y2;
        out[1] = z0^z1;
        return;
    }

    for(i = 0; i < size +1;i++){
        y[i] = x[i];
    }
 
    RefreshMasks(y,size+1);
    
    z[0] = Psi0(y[0],y[1],(int)size);
    for(i = 1;i<size;i++) {
        z[i]=Psi(y[0],y[i+1]);
    }
    
    B2Aext(A,y+1,mod,size-1);
    B2Aext(B,z,mod,size-1);
  
    for(i = 0;i<size-2;i++){
        out[i] = A[i] + B[i] % mod;
    }
    out[size-2] = A[size-2];
    out[size-1] = B[size-2];
}


void B2A(uint64_t *out, uint64_t *in, uint64_t mod, size_t size){
    uint64_t extended[MASKSIZE + 1];
    size_t i;
    extended[size]= 0;
    for(i = 0; i<size; i++) extended[i] = in[i];
    B2Aext(out,extended,mod,size);
}



static void B2A_bit_j(maskeda_t C, maskeda_t A, uint64_t xn, uint64_t mod, size_t n){
    uint64_t Aa = 0;
    maskeda_t B;
    uint64_t temp;
    uint64_t R;
    size_t i, j;
    for (i = 0; i<n-1; i++){
        Aa = (Aa + A[i]);
    } 
    for (i = 0; i<MASKSIZE; i++){ 
        B[i] = 0;
        C[i] = 0;
    }
    B[n-1] = rand64()% mod;
    
    // b0 = a0 - bn-1 mod q;
    temp = (mod - B[n-1]) % mod;
    B[0] = (A[0] + temp )%mod;

    for (j = 1; j<n-1; j++){
        R = rand64() % mod;

    //bj = aj - r mod q;
        temp = (mod - R) % mod;
        B[j] = (A[j] + temp) % mod;
        B[n-1] = (B[n-1] + R) % mod;
    }

    for (j = 0; j < n; j++){
    //cj = bj - 2*bj*xn mod q; 
        temp = (mod - ((2 * (B[j] * xn))%mod)) % mod;
        C[j] = (B[j] + temp) % mod;
    }
    
    //int b = ((C[0] + C[1] + C[2])%mod)%2;
    C[0] = (C[0] + xn) % mod; 
}

void B2A_bit(maskeda_t A, maskedb_t b, uint64_t mod){
    //Compute arithmetic value which unmask is equal to x1 xor x2 xor ... 
    maskeda_t C;
    size_t i, j;
    A[0] = b[0];
    for (j = 1; j<MASKSIZE; j++){
        B2A_bit_j(C,A,b[j], mod, (size_t)(j+1));
        for (i = 0; i<MASKSIZE; i++) A[i] = C[i];
    } 
}   



//-----------------------for 128-bit length value----------------------------


/*------------------------------------------------
SecMult128   :   Secure multiplication mod a power of 2 at order MASKORDER
input        :   Arithmetic maskings ina,inb (maskeda_t), Modulo mod (uint64_t)
output       :   Arithmetic maskings out1,out2 (maskeda_t)
------------------------------------------------*/
void SecMult128(maskeda_t outup,maskeda_t outdown, maskeda_t inaup, maskeda_t inadown,maskeda_t inbup,maskeda_t inbdown){
    uint64_t rup[MASKSIZE][MASKSIZE];
    uint64_t rdown[MASKSIZE][MASKSIZE];
    uint64_t tempup,tempdown,toutup,toutdown;
    size_t i, j;
    for(i = 0; i<MASKSIZE; i++){
        Mult128Bi(&outup[i],&outdown[i],inaup[i],inadown[i],inbup[i],inbdown[i]);
    }
    for(i = 0; i <MASKSIZE-1; i++){
        for(j = i+1; j<MASKSIZE; j++){
            rup[i][j] = rand64();
            rdown[i][j] = rand64();
            Mult128Bi(&tempup,&tempdown,inaup[i],inadown[i],inbup[j],inbdown[j]);
            Add128(&toutup,&toutdown,tempup,tempdown,rup[i][j],rdown[i][j]);
            rup[j][i]=toutup;rdown[j][i] = toutdown;
            Mult128Bi(&tempup,&tempdown,inaup[j],inadown[j],inbup[i],inbdown[i]);
            Add128(&toutup,&toutdown,tempup,tempdown,rup[j][i],rdown[j][i]);
            rup[j][i]=toutup;
            rdown[j][i]=toutdown;
            Add128(&tempup,&tempdown,~rup[i][j],~rdown[i][j],0,1); //Negation de r[i][j]
            Add128(&toutup,&toutdown,outup[i],outdown[i],tempup,tempdown);
            outup[i] = toutup;outdown[i]=toutdown;
            Add128(&toutup,&toutdown,outup[j],outdown[j],rup[j][i],rdown[j][i]);
            outup[j] = toutup;outdown[j]=toutdown;
            }
    }
}


/*------------------------------------------------
SecAdd128 :   Secure addition at order MASKORDER
input     :   Boolean maskings ina1,ina2, inb1,inb2 (maskedb_t),
              Number of shares size (int)
output    :   Arithmetic masking out (maskedb_t)
------------------------------------------------*/
void SecAdd128(uint64_t *out1,uint64_t *out, uint64_t *ina1,uint64_t *ina, uint64_t* inb1,uint64_t *inb, size_t size){
    uint64_t p[MASKSIZE],g[MASKSIZE],a[MASKSIZE],a2[MASKSIZE];
    uint64_t p1[MASKSIZE],g1[MASKSIZE],a1[MASKSIZE],a21[MASKSIZE];
    size_t i, j;
    int pow=1;
    for(i = 0; i<size; i++){ 
        p[i] = ina[i] ^ inb[i];
        p1[i] = ina1[i] ^inb1[i];
    }
    SecAnd(g,ina,inb,size);
    SecAnd(g1,ina1,inb1,size);
    for(j = 0; j<8-1; j++){
        for(i = 0; i<size; i++){
            a[i] = g[i] << pow;
            a1[i] = (g1[i] << pow)^(g[i]>>(64-pow));
        }
        SecAnd(a2,a,p,size);
        SecAnd(a21,a1,p1,size);
        for(i =0; i<size; i++) {
            g[i] ^= a2[i];
            g1[i] ^= a21[i];
            a2[i] = p[i] << pow;
            a21[i] = (p1[i]<<pow)^(p[i]>>(64-pow));
        }
        RefreshXOR_64(a2,a2,size);
        RefreshXOR_64(a21,a21,size);
        SecAnd(a,p,a2,size);
        SecAnd(a1,p1,a21,size);
        for(i = 0; i < size; i++) {
            p[i] = a[i];
            p1[i] = a1[i];
        }
        pow *= 2;
    }
    for(i = 0; i<size; i++) {
        a[i] = g[i] << pow;
        a1[i] = (g1[i] << pow)^(g[i]>>(64-pow));
    }
    SecAnd(a2,a,p,size);
    SecAnd(a21,a1,p1,size);
    for(i = 0; i<size; i++){
        g[i] ^= a2[i];
        g1[i] ^= a21[i];
        out[i] = ina[i]^inb[i]^(g[i]<<1);
        out1[i] = ina1[i]^inb1[i]^(g1[i]<<1)^(g[i]>>63);
    }
}



void A2B128(uint64_t *out1,uint64_t *out2, uint64_t *in1, uint64_t *in2, size_t size){
    uint64_t up[MASKSIZE],down[MASKSIZE];
    uint64_t up1[MASKSIZE],down1[MASKSIZE];
    uint64_t y[MASKSIZE],z[MASKSIZE];
    uint64_t y1[MASKSIZE],z1[MASKSIZE];
    size_t i;
    if(size==1){
        out1[0] = in1[0];
        out2[0] = in2[0];
        return;
    }
    else{
        for(i = 0; i < size/2; i++){
            down[i] = in1[i];
            down1[i] = in2[i];
        }
        for(i = 0; i < size-size/2; i++){ 
            up[i] = in1[i+size/2];
            up1[i] = in2[i+size/2];
        }

        A2B128(y,y1,down,down1,size/2);
        A2B128(z,z1,up,up1,size-size/2);

        for(i = size/2; i<size;i++){
            y[i] = 0;
            y1[i] = 0;
        }
        for(i = size-size/2;i<size;i++){
            z[i] = 0;
            z1[i] = 0;
        }
        
        RefreshXOR_64(y,y,size);
        RefreshXOR_64(z,z,size);
        RefreshXOR_64(y1,y1,size);
        RefreshXOR_64(z1,z1,size);
        SecAdd128(out1,out2,z,z1,y,y1,size);
    }
}


//For B2A128
static void Psi128(uint64_t *outup,uint64_t *outdown, uint64_t xu,uint64_t xd,uint64_t yu, uint64_t yd)
{
    uint64_t tempup, tempdown;
    Add128(&tempup,&tempdown,~yu,~yd,0,1);
    Add128(outup,outdown,tempup,tempdown,xu^yu,xd^yd);
  //return (x ^ y)-y;
}

//For B2A128
static void Psi0128(uint64_t *outup, uint64_t *outdown,uint64_t xu,uint64_t xd, uint64_t yu, uint64_t yd,size_t n)
{
    uint64_t tempup,tempdown;
    Psi128(outup,outdown,xu,xd,yu,yd);
    Mult128Bi(&tempup,&tempdown,xu,xd,0,(~((int)n)&1));
    *outup ^= tempup;
    *outdown ^= tempdown;
  //return Psi(x,y) ^ ((~n & 1) * x);
}

static void B2Aext128(maskeda_t outup, maskeda_t outdown, maskedb_t xu,maskedb_t xd, size_t size){
    uint64_t yu[MASKSIZE+1],yd[MASKSIZE+1];
    uint64_t zu[MASKSIZE],zd[MASKSIZE];
    uint64_t Au[MASKSIZE-1],Ad[MASKSIZE-1],Bu[MASKSIZE-1],Bd[MASKSIZE-1];
    size_t i;
    if(size==1){
        outdown[0] = xd[0]^xd[1];
        outup[0] = xu[0]^xu[1];
        return;
    }
    for(i = 0; i < size +1;i++){
        yd[i] = xd[i];
        yu[i] = xu[i];
    }
    RefreshMasks(yd,size+1);
    RefreshMasks(yu,size+1);
    Psi0128(&zu[0],&zd[0],yu[0],yd[0],yu[1],yd[1],size);
    for(i = 1;i<size;i++){
        Psi128(&zu[i],&zd[i],yu[0],yd[0],yu[i+1],yd[i+1]);
    }
    B2Aext128(Au,Ad,yu+1,yd+1,size-1);
    B2Aext128(Bu,Bd,zu,zd,size-1);
    for(i=0;i<size-2;i++){
        Add128(&outup[i],&outdown[i],Au[i],Ad[i],Bu[i],Bd[i]);
    }
    outup[size-2]=Au[size-2];outdown[size-2]=Ad[size-2];
    outup[size-1]=Bu[size-2];outdown[size-1]=Bd[size-2];
}


void B2A128(maskeda_t outup, maskeda_t outdown, maskedb_t inup, maskedb_t indown, size_t size){
    uint64_t extendedup[MASKSIZE+1],extendeddown[MASKSIZE+1];
    extendedup[size]= 0;extendeddown[size]=0;
    for(size_t i = 0; i<size; i++) {
        extendedup[i] = inup[i];
        extendeddown[i] = indown[i];
        }
    B2Aext128(outup,outdown,extendedup,extendeddown,size);
}
