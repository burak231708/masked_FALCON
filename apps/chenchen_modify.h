#ifndef CHENCHEN_MODIFY_H
#define CHENCHEN_MODIFY_H

#include <stddef.h> 
#include <stdint.h> 

#include "gadgets.h"


void SecFprUrshFloor(maskedb_t out, maskedb_t out2, maskedb_t in, maskeda_t c);
void SecFprUrshTrunc(maskedb_t out, maskedb_t in, maskeda_t c);
void SecFprAddDiv(maskedb_t out, maskedb_t in1, maskedb_t in2);
void SecFprComp(maskedb_t out, maskedb_t in1, maskedb_t in2);


#endif