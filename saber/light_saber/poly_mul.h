#ifndef POLY_MUL_H
#define POLY_MUL_H

#include "SABER_params.h"
#include <stdint.h>

void poly_mul_acc(const uint16_t a[LIGHT_SABER_N], const uint16_t b[LIGHT_SABER_N], uint16_t res[LIGHT_SABER_N]);

#endif