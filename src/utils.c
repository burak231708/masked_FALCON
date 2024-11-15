#include <assert.h> //assert for debug
#include <stdbool.h> //boolean type
#include <stdio.h> //printf
#include <stdlib.h>
#include <time.h>


#include "utils.h"



//Constants

#define SIZE              63U //64-1
#define HALF_SIZE         32U
#define HALF_BIT          4294967295U //eq. 0xffffffff 
#define RAND_GENERATOR_1  0xF108E4CD87654321UL 
#define RAND_GENERATOR_2  0x1525374657E5F50DUL
#define RAND_GENERATOR_3  0x8B459B95879A07F3UL 
#define ONE               1UL
#define THREE             3UL

//----------------------------------------------------------------------------------------

uint64_t rand64(void)
{
    static uint64_t ui64_rotor0, ui64_rotor1, ui64_feedback, ui64_seed;
    bool b_oneway = false;
    if(!b_oneway){
        ui64_seed = (uint64_t)rand();
        ui64_rotor0 = ui64_seed;
        ui64_rotor1 = ui64_seed * RAND_GENERATOR_1;
        b_oneway = true;
    }
    ui64_feedback =(ui64_rotor1 << ONE) ^ (ui64_rotor0 >> SIZE) ^ (ui64_rotor0);
    ui64_rotor1 = ui64_rotor0;
    ui64_rotor0 = ui64_feedback;
    return((ui64_rotor0 * RAND_GENERATOR_2) + RAND_GENERATOR_3);
}

uint64_t randmod(uint64_t ui64_mod)
{
    uint64_t ui64_res;

    ui64_res = ((uint64_t)rand()) % (ui64_mod);
    assert((ui64_res< ui64_mod));

    return ui64_res;
}

void print_binary_form(uint64_t ui64_in)
{
    int64_t ui64_i;
    printf("0b");
    for(ui64_i = SIZE; (0 <= ui64_i); ui64_i--){
        printf("%ld",(ui64_in >> ui64_i) & ONE);
    }
    printf("\n");
}

//return outup and outdown such as 
//                    out = outup * 2^64 + outdown
void Mult128(uint64_t *ui64_outup, uint64_t *ui64_outdown, 
             uint64_t ui64_in1, uint64_t ui64_in2)
{
    uint64_t ui64_au, ui64_ad, ui64_bu, ui64_bd;
    uint64_t ui64_multuu, ui64_multud, ui64_multdu, ui64_multdd;
    uint64_t ui64_addlow, ui64_addup;
    
    ui64_au = ui64_in1 >> HALF_SIZE;
    ui64_ad = ui64_in1 & HALF_BIT;
    ui64_bu = ui64_in2 >> HALF_SIZE;
    ui64_bd = ui64_in2 & HALF_BIT;

    ui64_multuu = ui64_au * ui64_bu;
    ui64_multud = ui64_au * ui64_bd;
    ui64_multdu = ui64_ad * ui64_bu;
    ui64_multdd = ui64_ad * ui64_bd;

    *ui64_outup = ui64_multuu;
    *ui64_outdown = ui64_multdd & HALF_BIT;
    
    ui64_addlow = (ui64_multud & HALF_BIT) + (ui64_multdu & HALF_BIT);
    ui64_addlow = ui64_addlow + (ui64_multdd >> HALF_SIZE);
    ui64_addup = (ui64_multud >> HALF_SIZE) + (ui64_multdu >> HALF_SIZE);
    ui64_addup = ui64_addup + + ((ui64_addlow >> HALF_SIZE) & THREE);
    *ui64_outdown += ui64_addlow << HALF_SIZE;
    *ui64_outup += ui64_addup;
}

void Add128(uint64_t *ui64_outup, uint64_t *ui64_outdown, uint64_t ui64_in1up, 
            uint64_t ui64_in1down, uint64_t ui64_in2up, uint64_t ui64_in2down)
{
    uint64_t ui64_in12_A, ui64_in12_B, ui64_in22_A, ui64_in22_B;

    ui64_in12_A = ui64_in1down >> HALF_SIZE;
    ui64_in12_B = ui64_in1down & HALF_BIT;
    ui64_in22_A = ui64_in2down >> HALF_SIZE;
    ui64_in22_B = ui64_in2down & HALF_BIT;

    ui64_in12_B += ui64_in22_B;
    ui64_in12_A += ui64_in22_A + ((ui64_in12_B >> HALF_SIZE) & ONE);

    *ui64_outdown = (ui64_in12_B & HALF_BIT)^((ui64_in12_A & HALF_BIT) << HALF_SIZE);

    *ui64_outup = ui64_in1up + ui64_in2up + ((ui64_in12_A >> HALF_SIZE) & THREE);
}

//----------------------------------------------------------------------------------------


void Mult128Bi(uint64_t *ui64_outup, uint64_t *ui64_outdown, uint64_t ui64_in1up, 
               uint64_t ui64_in1down, uint64_t ui64_in2up, uint64_t ui64_in2down)
{
    /*
    (u1*2^64 + d1)*(u2*2^64 + d2) = u1u2*2^128 + d1d2 + 
    (d1u2+d2u1)*2^64 = d1d2 + (d1u2+d2u1)<<64 mod 2^128
    */
    uint64_t ui64_d1d2u,ui64_d1d2d,ui64_d1u2u,ui64_d1u2d,ui64_d2u1u,ui64_d2u1d;

    Mult128(&ui64_d1d2u, &ui64_d1d2d, ui64_in1down, ui64_in2down);
    Mult128(&ui64_d1u2u, &ui64_d1u2d, ui64_in1down, ui64_in2up);
    Mult128(&ui64_d2u1u, &ui64_d2u1d, ui64_in1up, ui64_in2down);

    *ui64_outup = ui64_d1d2u;
    *ui64_outdown = ui64_d1d2d;

    Add128(&ui64_d1d2u, &ui64_d1d2d, ui64_d1u2u, ui64_d1u2d, ui64_d2u1u, ui64_d2u1d); 
    // A = d1u2 +d2u1
    ui64_d2u1u = *ui64_outup;
    ui64_d2u1d = *ui64_outdown;
    Add128(ui64_outup, ui64_outdown, ui64_d2u1u, ui64_d2u1d, ui64_d1d2d, 0); 
    //out = d1d2 + A<<64 = {d1d2u + Ad pour up; d1d2d pour down}
}


uint64_t subq(uint64_t ina, uint64_t inb, uint64_t mod)
{
    uint64_t res1, res2;
    res1 = (ina - inb) % mod;
    res2 = (ina - inb + mod) % mod;
    if (ina < inb){
        return(res2);
    }else{
        return(res1);
    }
}