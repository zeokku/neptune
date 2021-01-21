#include <stdio.h>
#include "api.h"
#include "poly.h"
#include "poly_mul.h"
#include "pack_unpack.h"
#include "cbd.h"
#include "../fips202.h"


namespace light_saber
{
void MatrixVectorMul(const uint16_t A[LIGHT_SABER_L][LIGHT_SABER_L][LIGHT_SABER_N], const uint16_t s[LIGHT_SABER_L][LIGHT_SABER_N], uint16_t res[LIGHT_SABER_L][LIGHT_SABER_N], int16_t transpose)
{
	int i, j;
	for (i = 0; i < LIGHT_SABER_L; i++)
	{
		for (j = 0; j < LIGHT_SABER_L; j++)
		{
			if (transpose == 1)
			{
				poly_mul_acc(A[j][i], s[j], res[i]);
			}
			else
			{
				poly_mul_acc(A[i][j], s[j], res[i]);
			}
		}
	}
}

void InnerProd(const uint16_t b[LIGHT_SABER_L][LIGHT_SABER_N], const uint16_t s[LIGHT_SABER_L][LIGHT_SABER_N], uint16_t res[LIGHT_SABER_N])
{
	int j;
	for (j = 0; j < LIGHT_SABER_L; j++)
	{
		poly_mul_acc(b[j], s[j], res);
	}
}

void GenMatrix(uint16_t A[LIGHT_SABER_L][LIGHT_SABER_L][LIGHT_SABER_N], const uint8_t seed[LIGHT_SABER_SEEDBYTES])
{
	uint8_t buf[LIGHT_SABER_L * LIGHT_SABER_POLYVECBYTES];
	int i;

	shake128(buf, sizeof(buf), seed, LIGHT_SABER_SEEDBYTES);

	for (i = 0; i < LIGHT_SABER_L; i++)
	{
		BS2POLVECq(buf + i * LIGHT_SABER_POLYVECBYTES, A[i]);
	}
}

void GenSecret(uint16_t s[LIGHT_SABER_L][LIGHT_SABER_N], const uint8_t seed[LIGHT_SABER_NOISE_SEEDBYTES])
{
	uint8_t buf[LIGHT_SABER_L * LIGHT_SABER_POLYCOINBYTES];
	size_t i;

	shake128(buf, sizeof(buf), seed, LIGHT_SABER_NOISE_SEEDBYTES);

	for (i = 0; i < LIGHT_SABER_L; i++)
	{
		cbd(s[i], buf + i * LIGHT_SABER_POLYCOINBYTES);
	}
}

}
