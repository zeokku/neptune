#include "SABER_params.h"

//namespace saber{
int saber_kem_keypair(unsigned char *pk, unsigned char *sk);
int saber_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int saber_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
//} // namespace saber