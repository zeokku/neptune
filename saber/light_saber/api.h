#include "SABER_params.h"

int light_saber_kem_keypair(unsigned char *pk, unsigned char *sk);
int light_saber_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int light_saber_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);