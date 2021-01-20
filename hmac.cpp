#include "hmac.h"

namespace neptune
{
    //no verification, cuz used internally
    //tools.ietf.org/html/rfc2104
    //returns newely allocated result + its length
    void hmac(packets::eHashing hash_alg, byte *data, size_t data_sz, byte *key, size_t key_sz, byte *result, size_t &result_sz)
    {
        //B - block size
        byte ipad[WC_SHA3_256_BLOCK_SIZE];
        byte opad[WC_SHA3_256_BLOCK_SIZE];

        memset(ipad, 0x36, sizeof(ipad));
        memset(opad, 0x5C, sizeof(opad));

        //not timing resistant?
        for (size_t i = 0; i < key_sz; i += 1)
        {
            ipad[i] ^= key[i];
            opad[i] ^= key[i];
        }

        size_t inner_sz = sizeof(ipad) + data_sz;
        byte *inner = new byte[inner_sz];

        memcpy(inner, ipad, sizeof(ipad));
        memcpy(inner + sizeof(ipad), data, data_sz);

        byte innerSum[SHA3_256_DIGEST_SIZE];

        wc_Sha3 sha3;

        wc_InitSha3_256(&sha3, NULL, 0);

        wc_Sha3_256_Update(&sha3, inner, inner_sz);

        wc_Sha3_256_Final(&sha3, innerSum);

        delete[] inner;

        //

        size_t outer_sz = sizeof(opad) + SHA3_256_DIGEST_SIZE;
        byte *outer = new byte[outer_sz];

        memcpy(outer, opad, sizeof(opad));
        memcpy(outer + sizeof(opad), innerSum, SHA3_256_DIGEST_SIZE);

        //

        byte resultSum[SHA3_256_DIGEST_SIZE];

        wc_Sha3_256_Update(&sha3, outer, outer_sz);

        wc_Sha3_256_Final(&sha3, resultSum);

        delete[] outer;

        //

        wc_Sha3_256_Free(&sha3);

        print_bytes(resultSum, sizeof(resultSum));
    }

} // namespace neptune