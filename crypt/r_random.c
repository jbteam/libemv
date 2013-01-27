/*  
    R_RANDOM.C - random objects for RSAEURO  
    Copyright(C) 2002 by charry, charry@email.com.cn  
    RSAEURO - RSA Library compatible with RSAREF(tm) 2.0.  
  
    Random Objects routines, based heavily on RSAREF(tm) random objects  
    code.  New routines REQUIRE and ANSI Standard C compiler that has  
    clock() and time() functions.  
 */   
   
#include <stdlib.h>
   
#ifdef MSDOS   
    #include <sys\types.h>   
#endif   
   
#include "rsaeuro.h"   
#include "r_random.h"   
#include "md5.h"   
   
#define RANDOM_BYTES_RQ 256   
   
/* We use more seed data for an internally created object */   
   
#define RANDOM_BYTES_RQINT 512      
   
/* Get the number of seed byte still required by the object */   
   
int R_GetRandomBytesNeeded(bytesNeeded, random)   
unsigned int *bytesNeeded;      /* number of mix-in bytes needed */   
R_RANDOM_STRUCT *random;        /* random structure */   
{   
    *bytesNeeded = random->bytesNeeded;   
   
    return(ID_OK);   
}   
   
int R_GenerateBytes(block, len, random)   
unsigned char *block;                             /* block */   
unsigned int len;                                 /* length of block */   
R_RANDOM_STRUCT *random;                          /* random structure */   
{   
    MD5_CTX context;   
    unsigned int avail, i;   
   
    if(random->bytesNeeded)   
        return(RE_NEED_RANDOM);   
   
    avail = random->outputAvailable;   
   
    while(avail < len) {   
        R_memcpy((POINTER)block, (POINTER)&random->output[16-avail], avail);   
        len -= avail;   
        block += avail;   
   
        /* generate new output */   
   
        MD5Init(&context);   
        MD5Update(&context, random->state, 16);   
        MD5Final(random->output, &context);   
        avail = 16;   
   
        /* increment state */   
   
        for(i = 16; i > 0; i--)   
            if(random->state[i-1]++)   
                break;   
    }   
   
    R_memcpy((POINTER)block, (POINTER)&random->output[16-avail], len);   
    random->outputAvailable = avail - len;   
   
    return(ID_OK);   
}   
