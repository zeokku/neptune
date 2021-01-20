#include "common.h"
#include "debug.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha3.h>

#include "packets/handshake.pb.h"

namespace neptune
{
    void hmac(packets::eHashing hash_alg, byte *key, size_t key_sz, byte *data, size_t data_sz, byte *&result, size_t &result_sz);
}