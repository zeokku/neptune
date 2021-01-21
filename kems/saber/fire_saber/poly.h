#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "SABER_params.h"


namespace fire_saber
{
void MatrixVectorMul(const uint16_t a[FIRE_SABER_L][FIRE_SABER_L][FIRE_SABER_N], const uint16_t s[FIRE_SABER_L][FIRE_SABER_N], uint16_t res[FIRE_SABER_L][FIRE_SABER_N], int16_t transpose);
void InnerProd(const uint16_t b[FIRE_SABER_L][FIRE_SABER_N], const uint16_t s[FIRE_SABER_L][FIRE_SABER_N], uint16_t res[FIRE_SABER_N]);
void GenMatrix(uint16_t a[FIRE_SABER_L][FIRE_SABER_L][FIRE_SABER_N], const uint8_t seed[FIRE_SABER_SEEDBYTES]);
void GenSecret(uint16_t s[FIRE_SABER_L][FIRE_SABER_N], const uint8_t seed[FIRE_SABER_NOISE_SEEDBYTES]);

#endif

}
