#ifndef INDCPA_H
#define INDCPA_H

#include "SABER_params.h"


namespace fire_saber
{
void indcpa_kem_keypair(uint8_t pk[FIRE_SABER_INDCPA_PUBLICKEYBYTES], uint8_t sk[FIRE_SABER_INDCPA_SECRETKEYBYTES]);
void indcpa_kem_enc(const uint8_t m[FIRE_SABER_KEYBYTES], const uint8_t seed_sp[FIRE_SABER_NOISE_SEEDBYTES], const uint8_t pk[FIRE_SABER_INDCPA_PUBLICKEYBYTES], uint8_t ciphertext[FIRE_SABER_BYTES_CCA_DEC]);
void indcpa_kem_dec(const uint8_t sk[FIRE_SABER_INDCPA_SECRETKEYBYTES], const uint8_t ciphertext[FIRE_SABER_BYTES_CCA_DEC], uint8_t m[FIRE_SABER_KEYBYTES]);

#endif
}
