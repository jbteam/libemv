/* 
	GLOBAL.H - RSAEURO types and constants 
    Copyright(C) 2002 by charry, charry@email.com.cn 
	RSAEURO - RSA Library compatible with RSAREF 2.0. 
 
	Global types and contants file. 
 */ 
 
#ifndef _GLOBAL_H_ 
#define _GLOBAL_H_ 
 
/* PROTOTYPES should be set to one if and only if the compiler supports 
		 function argument prototyping. 
	 The following makes PROTOTYPES default to 1 if it has not already been 
		 defined as 0 with C compiler flags. 
 */ 
 
#ifndef PROTOTYPES 
#define PROTOTYPES 1 
#endif 
 
/* POINTER defines a generic pointer type */ 
 
typedef unsigned char *POINTER; 
 
/* UINT2 defines a two byte word */ 
 
typedef unsigned short int UINT2; 
 
/* UINT4 defines a four byte word */ 
 
typedef unsigned long int UINT4; 
 
/* BYTE defines a unsigned character */ 
 
typedef unsigned char BYTE; 
 
/* internal signed value */ 
 
typedef signed long int signeddigit; 
 
#ifndef NULL_PTR 
#define NULL_PTR ((POINTER)0) 
#endif 
 
#ifndef UNUSED_ARG 
#define UNUSED_ARG(x) x = *(&x); 
#endif 
 
/* PROTO_LIST is defined depending on how PROTOTYPES is defined above. 
	 If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it 
	 returns an empty list. 
 */ 
 
#if PROTOTYPES 
#define PROTO_LIST(list) list 
#else 
#define PROTO_LIST(list) () 
#endif 
 
#endif /* _GLOBAL_H_ */ 
