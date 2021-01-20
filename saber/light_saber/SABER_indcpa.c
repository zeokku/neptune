#include <string.h>
#include <stdint.h>
#include "SABER_indcpa.h"
#include "poly.h"
#include "pack_unpack.h"
#include "poly_mul.c"
#include "../rng.h"
#include "fips202.h"
#include "SABER_params.h"

#define h1 (1 << (LIGHT_SABER_EQ - LIGHT_SABER_EP - 1))
#define h2 ((1 << (LIGHT_SABER_EP - 2)) - (1 << (LIGHT_SABER_EP - LIGHT_SABER_ET - 1)) + (1 << (LIGHT_SABER_EQ - LIGHT_SABER_EP - 1)))

void indcpa_kem_keypair(uint8_t pk[LIGHT_SABER_INDCPA_PUBLICKEYBYTES], uint8_t sk[LIGHT_SABER_INDCPA_SECRETKEYBYTES])
{
	uint16_t A[LIGHT_SABER_L][LIGHT_SABER_L][LIGHT_SABER_N];
	uint16_t s[LIGHT_SABER_L][LIGHT_SABER_N];
	uint16_t b[LIGHT_SABER_L][LIGHT_SABER_N] = {0};

	uint8_t seed_A[LIGHT_SABER_SEEDBYTES];
	uint8_t seed_s[LIGHT_SABER_NOISE_SEEDBYTES];
	int i, j;

	randombytes(seed_A, LIGHT_SABER_SEEDBYTES);
	shake128(seed_A, LIGHT_SABER_SEEDBYTES, seed_A, LIGHT_SABER_SEEDBYTES); // for not revealing system RNG state
	randombytes(seed_s, LIGHT_SABER_NOISE_SEEDBYTES);

	GenMatrix(A, seed_A);
	GenSecret(s, seed_s);
	MatrixVectorMul(A, s, b, 1);

	for (i = 0; i < LIGHT_SABER_L; i++)
	{
		for (j = 0; j < LIGHT_SABER_N; j++)
		{
			b[i][j] = (b[i][j] + h1) >> (LIGHT_SABER_EQ - LIGHT_SABER_EP);
		}
	}

	POLVECq2BS(sk, s);
	POLVECp2BS(pk, b);
	memcpy(pk + LIGHT_SABER_POLYVECCOMPRESSEDBYTES, seed_A, sizeof(seed_A));
}

void indcpa_kem_enc(const uint8_t m[LIGHT_SABER_KEYBYTES], const uint8_t seed_sp[LIGHT_SABER_NOISE_SEEDBYTES], const uint8_t pk[LIGHT_SABER_INDCPA_PUBLICKEYBYTES], uint8_t ciphertext[LIGHT_SABER_BYTES_CCA_DEC])
{
	uint16_t A[LIGHT_SABER_L][LIGHT_SABER_L][LIGHT_SABER_N];
	uint16_t sp[LIGHT_SABER_L][LIGHT_SABER_N];
	uint16_t bp[LIGHT_SABER_L][LIGHT_SABER_N] = {0};
	uint16_t vp[LIGHT_SABER_N] = {0};
	uint16_t mp[LIGHT_SABER_N];
	uint16_t b[LIGHT_SABER_L][LIGHT_SABER_N];
	int i, j;
	const uint8_t *seed_A = pk + LIGHT_SABER_POLYVECCOMPRESSEDBYTES;

	GenMatrix(A, seed_A);
	GenSecret(sp, seed_sp);
	MatrixVectorMul(A, sp, bp, 0);

	for (i = 0; i < LIGHT_SABER_L; i++)
	{
		for (j = 0; j < LIGHT_SABER_N; j++)
		{
			bp[i][j] = (bp[i][j] + h1) >> (LIGHT_SABER_EQ - LIGHT_SABER_EP);
		}
	}

	POLVECp2BS(ciphertext, bp);
	BS2POLVECp(pk, b);
	InnerProd(b, sp, vp);

	BS2POLmsg(m, mp);

	for (j = 0; j < LIGHT_SABER_N; j++)
	{
		vp[j] = (vp[j] - (mp[j] << (LIGHT_SABER_EP - 1)) + h1) >> (LIGHT_SABER_EP - LIGHT_SABER_ET);
	}

	POLT2BS(ciphertext + LIGHT_SABER_POLYVECCOMPRESSEDBYTES, vp);
}

void indcpa_kem_dec(const uint8_t sk[LIGHT_SABER_INDCPA_SECRETKEYBYTES], const uint8_t ciphertext[LIGHT_SABER_BYTES_CCA_DEC], uint8_t m[LIGHT_SABER_KEYBYTES])
{

	uint16_t s[LIGHT_SABER_L][LIGHT_SABER_N];
	uint16_t b[LIGHT_SABER_L][LIGHT_SABER_N];
	uint16_t v[LIGHT_SABER_N] = {0};
	uint16_t cm[LIGHT_SABER_N];
	int i;

	BS2POLVECq(sk, s);
	BS2POLVECp(ciphertext, b);
	InnerProd(b, s, v);
	BS2POLT(ciphertext + LIGHT_SABER_POLYVECCOMPRESSEDBYTES, cm);

	for (i = 0; i < LIGHT_SABER_N; i++)
	{
		v[i] = (v[i] + h2 - (cm[i] << (LIGHT_SABER_EP - LIGHT_SABER_ET))) >> (LIGHT_SABER_EP - 1);
	}

	POLmsg2BS(m, v);
}
