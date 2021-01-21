
#include "SABER_params.h"

namespace fire_saber
{
    int kem_keypair(unsigned char *pk, unsigned char *sk);
    int kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
    int kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
} // namespace fire_saber
