
#include "SABER_params.h"

int kem_keypair(unsigned char *pk, unsigned char *sk);
int kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

// #undef FIRE_SABER_L
// #undef FIRE_SABER_MU
// #undef FIRE_SABER_ET
// #undef FIRE_SABER_EQ
// #undef FIRE_SABER_EP
// #undef FIRE_SABER_N
// #undef FIRE_SABER_SEEDBYTES
// #undef FIRE_SABER_NOISE_SEEDBYTES
// #undef FIRE_SABER_KEYBYTES
// #undef FIRE_SABER_HASHBYTES
// #undef FIRE_SABER_POLYCOINBYTES
// #undef FIRE_SABER_POLYBYTES
// #undef FIRE_SABER_POLYVECBYTES
// #undef FIRE_SABER_POLYCOMPRESSEDBYTES
// #undef FIRE_SABER_POLYVECCOMPRESSEDBYTES
// #undef FIRE_SABER_SCALEBYTES_KEM
// #undef FIRE_SABER_INDCPA_PUBLICKEYBYTES
// #undef FIRE_SABER_INDCPA_SECRETKEYBYTES
// #undef FIRE_SABER_PUBLICKEYBYTES
// #undef FIRE_SABER_SECRETKEYBYTES
// #undef FIRE_SABER_BYTES_CCA_DEC
// #undef FIRE_SABER_CIPHERTEXTBYTES