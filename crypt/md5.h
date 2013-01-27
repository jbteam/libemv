/*  
	MD5.H - header file for MD5.C 
	Copyright(C) 2002 by charry, charry@email.com.cn 
 */ 
 
/* MD5 context. */ 

#ifdef __cplusplus
extern "C" {
#endif
 
typedef struct { 
  UINT4 state[4];                                   /* state (ABCD) */ 
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */ 
  unsigned char buffer[64];                         /* input buffer */ 
} MD5_CTX; 
 
void MD5Init PROTO_LIST ((MD5_CTX *)); 
void MD5Update PROTO_LIST 
  ((MD5_CTX *, unsigned char *, unsigned int)); 
void MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *)); 

#ifdef __cplusplus
}
#endif
