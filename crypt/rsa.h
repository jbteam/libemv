/* 
	RSA.H - header file for RSA.C 
    Copyright(C) 2002 by charry, charry@email.com.cn 
	RSAEURO - RSA Library compatible with RSAREF 2.0. 
 
	RSA Routines Header File. 
 */ 

#ifdef __cplusplus
extern "C"
{
#endif
 
int RSAPublicEncrypt PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int, 
    R_RSA_PUBLIC_KEY *, R_RANDOM_STRUCT *)); 
int RSAPrivateEncrypt PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int, 
    R_RSA_PRIVATE_KEY *)); 
int RSAPublicDecrypt PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int, 
    R_RSA_PUBLIC_KEY *)); 
int RSAPrivateDecrypt PROTO_LIST ((unsigned char *, unsigned int *, unsigned char *, unsigned int, 
    R_RSA_PRIVATE_KEY *)); 

#ifdef __cplusplus
}
#endif