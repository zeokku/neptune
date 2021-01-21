#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include "SABER_params.h"


namespace light_saber
{
void MatrixVectorMul(const uint16_t a[LIGHT_SABER_L][LIGHT_SABER_L][LIGHT_SABER_N], const uint16_t s[LIGHT_SABER_L][LIGHT_SABER_N], uint16_t res[LIGHT_SABER_L][LIGHT_SABER_N], int16_t transpose);
void InnerProd(const uint16_t b[LIGHT_SABER_L][LIGHT_SABER_N], const uint16_t s[LIGHT_SABER_L][LIGHT_SABER_N], uint16_t res[LIGHT_SABER_N]);
void GenMatrix(uint16_t a[LIGHT_SABER_L][LIGHT_SABER_L][LIGHT_SABER_N], const uint8_t seed[LIGHT_SABER_SEEDBYTES]);
void GenSecret(uint16_t s[LIGHT_SABER_L][LIGHT_SABER_N], const uint8_t seed[LIGHT_SABER_NOISE_SEEDBYTES]);

#endif

}
