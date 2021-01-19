#ifndef API_H
#define API_H

#include "SABER_params.h"

#if SABER_L == 2
	#define SABER_ALGNAME "LightSaber"
#elif SABER_L == 3
	#define SABER_ALGNAME "Saber"
#elif SABER_L == 4
	#define SABER_ALGNAME "FireSaber"
#else
	#error "Unsupported SABER parameter."
#endif

//#define CRYPTO_SECRETKEYBYTES SABER_SECRETKEYBYTES
//#define CRYPTO_PUBLICKEYBYTES SABER_PUBLICKEYBYTES
//#define CRYPTO_BYTES SABER_KEYBYTES
//#define SABER_CIPHERTEXTBYTES SABER_BYTES_CCA_DEC

int saber_kem_keypair(unsigned char *pk, unsigned char *sk);
int saber_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int saber_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif /* api_h */
