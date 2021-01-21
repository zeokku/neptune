
#include <iostream>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/aes.h>

#include <wolfssl/wolfcrypt/sha3.h>

#include <wolfssl/wolfcrypt/ecc.h>

#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/ed448.h>

#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/curve448.h>

#include "packets/handshake.pb.h"

#include <string.h>

#include "debug.h"

#include "kems/saber/rng.h"
#include "kems/saber/api.h"

#include "hmac.h"

//use hashing to generate seed out of ranndom bytes not to

using namespace std;
using namespace neptune::packets;

int main()
{

    int wc_res;

    WC_RNG rng;
    wc_res = wc_InitRng(&rng);
    if (wc_res != 0)
    {
        printf("Rng init: %s", wc_GetErrorString(wc_res));
    }

    // byte *hmac;
    // size_t outsize;

    // neptune::hmac(eHashing::SHA3_256, (byte *)("asss"), 4, (byte *)"asss", 4, hmac, outsize);

    // print_bytes(hmac, outsize);

    //####################

    //so linker did actually merge identical functions so flavors don't work

    //fuck this all just wrap each shit in own namespace

    uint8_t pk[FIRE_SABER_PUBLICKEYBYTES];
    uint8_t sk[FIRE_SABER_SECRETKEYBYTES];
    uint8_t c[FIRE_SABER_CIPHERTEXTBYTES];
    uint8_t k_a[FIRE_SABER_KEYBYTES], k_b[FIRE_SABER_KEYBYTES];

    unsigned char entropy_input[48];
    wc_res = wc_RNG_GenerateBlock(&rng, entropy_input, sizeof(entropy_input));

    randombytes_init(entropy_input, NULL, 256);

    fire_saber::kem_keypair(pk, sk);

    printf("pk (%d)\n", sizeof(pk));
    print_bytes(pk, sizeof(pk));

    printf("sk (%d)\n", sizeof(sk));
    print_bytes(sk, sizeof(sk));

    fire_saber::kem_enc(c, k_a, pk);
    fire_saber::kem_dec(k_b, c, sk);

    printf("k_a\n");
    print_bytes(k_a, sizeof(k_a));

    printf("k_b\n");
    print_bytes(k_b, sizeof(k_b));

    //$$$$$$$$$$$$$$$$$$$$$

    uint8_t pk2[SABER_PUBLICKEYBYTES];
    uint8_t sk2[SABER_SECRETKEYBYTES];
    uint8_t c2[SABER_CIPHERTEXTBYTES];
    uint8_t k_a2[SABER_KEYBYTES], k_b2[SABER_KEYBYTES];

    saber::kem_keypair(pk2, sk2);

    printf("pk (%d)\n", sizeof(pk2));
    print_bytes(pk2, sizeof(pk2));

    printf("sk (%d)\n", sizeof(sk2));
    print_bytes(sk2, sizeof(sk2));

    saber::kem_enc(c2, k_a2, pk2);
    saber::kem_dec(k_b2, c2, sk2);

    printf("k_a2\n");
    print_bytes(k_a2, sizeof(k_a2));

    printf("k_b2\n");
    print_bytes(k_b2, sizeof(k_b2));

    return 0;

    //#######

    // curve25519_key bob;
    // wc_curve25519_init(&bob);
    // ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &bob);

    // printf("ret: %d\n", ret);

    // curve25519_key alice;
    // wc_curve25519_init(&alice);
    // ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, &alice);

    // //if not define length returns BAD_FUNC_ARG randomly for some reason
    // word32 bob_shared_size = CURVE25519_KEYSIZE;
    // byte bob_shared[CURVE25519_KEYSIZE];
    // ret = wc_curve25519_shared_secret(&bob, &alice, bob_shared, &bob_shared_size);

    // //if !0 err

    // word32 alice_shared_size = CURVE25519_KEYSIZE;
    // byte alice_shared[CURVE25519_KEYSIZE];
    // ret = wc_curve25519_shared_secret(&alice, &bob, alice_shared, &alice_shared_size);

    // printf("bob shared key (%d):\n", bob_shared_size);
    // print_bytes(bob_shared, sizeof(bob_shared));

    // printf("alice shared key (%d):\n", alice_shared_size);
    // print_bytes(alice_shared, sizeof(alice_shared));

    // wc_curve25519_free(&bob);
    // wc_curve25519_free(&alice);

    // if (memcmp(bob_shared, alice_shared, CURVE25519_KEYSIZE) == 0)
    // {
    //     printf("keys match!\n");
    // }
    // else
    // {
    //     printf("keys don't match!\n");
    // }

    // //

    // Handshake *hs = new Handshake();
    // KEM_PublicKey *kem_pk = hs->add_kem_keys();
    // kem_pk->set_key(bob_shared, CURVE25519_KEYSIZE);

    // //kem_pk->clear_key

    // print_bytes((byte *)(kem_pk->key().c_str()), CURVE25519_KEYSIZE);

    // hs->~Handshake();

    //$$$$

    // ed25519_key bob;
    // wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &bob);

    // printf("- bob -\n");
    // printf("k:\n");
    // print_bytes(bob.k, sizeof(bob.k));

    // printf("p:\n");
    // print_bytes(bob.p, sizeof(bob.p));

    // ed25519_key alice;
    // wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &alice);

    // printf("- alice -\n");
    // printf("k:\n");
    // print_bytes(alice.k, sizeof(alice.k));

    // printf("p:\n");
    // print_bytes(alice.p, sizeof(alice.p));

    //printf("free key\n");
    //free does nullify memory, though it's better to fill it with some random
    //wc_ed25519_free(&bob);

    //wc_RNG_GenerateBlock(&rng, reinterpret_cast<byte *>(&bob), sizeof(bob));

    //wc_RNG_HealthTest();
    //wc_rng_

    // printf("k:\n");
    // print_bytes(bob.k, 64);

    // printf("p:\n");
    // print_bytes(bob.p, 32);

    // string *ec_pub_key = new string(reinterpret_cast<const char *>(bob.p), sizeof(bob.p));

    // Handshake *hs = new Handshake();
    // KEM_PublicKey *kem_pk = hs->add_kem_keys();
    // kem_pk->set_allocated_key(ec_pub_key);

    // hs->~Handshake();

    //    wc_FreeRng(&rng);

    return 0;

    // ecc_key key1, key2;

    // ret = wc_ecc_init(&key1);
    // if (ret != 0)
    // {
    //     printf("Key1 init: %s", wc_GetErrorString(ret));
    // }

    // ret = wc_ecc_make_key(&rng, 32, &key1);
    // if (ret != 0)
    // {
    //     printf("Key1 gen: %s", wc_GetErrorString(ret));
    // }

    // byte priv1Bytes[1024];
    // word32 priv1BytesSz = sizeof(priv1Bytes);
    // ret = wc_ecc_export_private_only(&key1, priv1Bytes, &priv1BytesSz);
    // if (ret != 0)
    // {
    //     printf("Key1 private export: %s", wc_GetErrorString(ret));
    // }
    // else
    // {
    //     printf("\nKey 1 private (%d):\n", priv1BytesSz);
    //     print_bytes(priv1Bytes, priv1BytesSz);
    // }

    // byte pub1Bytes[1024];
    // word32 pub1BytesSz = sizeof(pub1Bytes);
    // ret = wc_ecc_export_x963(&key1, pub1Bytes, &pub1BytesSz);
    // if (ret != 0)
    // {
    //     printf("Key1 public export: %s", wc_GetErrorString(ret));
    // }
    // else
    // {
    //     printf("\nKey1 public (%d):\n", pub1BytesSz);
    //     print_bytes(pub1Bytes, pub1BytesSz);
    // }

    // ret = wc_ecc_init(&key2);
    // if (ret != 0)
    // {
    //     printf("Key2 init: %s", wc_GetErrorString(ret));
    // }

    // ret = wc_ecc_make_key(&rng, 32, &key2);
    // if (ret != 0)
    // {
    //     printf("Key2 gen: %s", wc_GetErrorString(ret));
    // }

    // byte priv2Bytes[1024];
    // word32 priv2BytesSz = sizeof(priv2Bytes);
    // ret = wc_ecc_export_private_only(&key2, priv2Bytes, &priv2BytesSz);
    // if (ret != 0)
    // {
    //     printf("Key2 private export: %s", wc_GetErrorString(ret));
    // }
    // else
    // {
    //     printf("\nKey2 private (%d):\n", priv2BytesSz);
    //     print_bytes(priv2Bytes, priv2BytesSz);
    // }

    // byte pub2Bytes[1024];
    // word32 pub2BytesSz = sizeof(pub2Bytes);
    // ret = wc_ecc_export_x963(&key2, pub2Bytes, &pub2BytesSz);
    // if (ret != 0)
    // {
    //     printf("Key2 public export: %s", wc_GetErrorString(ret));
    // }
    // else
    // {
    //     printf("\nKey2 public (%d):\n", pub2BytesSz);
    //     print_bytes(pub2Bytes, pub2BytesSz);
    // }

    // key1.rng = &rng;
    // //key2.rng = &rng;

    // byte secret[1024];
    // word32 secretSz = sizeof(secret);

    // ret = wc_ecc_shared_secret(&key1, &key2, secret, &secretSz);
    // if (ret != 0)
    // {
    //     printf("Shared gen: %s", wc_GetErrorString(ret));
    // }
    // else
    // {
    //     printf("\nShared gen (%d):\n", secretSz);
    //     print_bytes(secret, secretSz);
    // }

    // //ecc_curve_id::ECC_X448;

    // wc_ecc_free(&key2);
    // wc_ecc_free(&key1);

    // wc_FreeRng(&rng);

    // return 0;

    // byte shaSum[SHA3_256_DIGEST_SIZE];
    // byte buffer[] = {0x0a};

    // wc_Sha3 sha3;

    // wc_InitSha3_256(&sha3, NULL, 0);

    // wc_Sha3_256_Update(&sha3, buffer, 1);

    // wc_Sha3_256_Final(&sha3, shaSum);

    // wc_Sha3_256_Free(&sha3);

    // print_bytes(shaSum, SHA3_256_DIGEST_SIZE);

    // ecc_key key;
    // wc_ecc_init(&key);

    // WC_RNG rng;
    // wc_InitRng(&rng);

    // int curveId = ECC_SECP521R1;
    // int keySize = wc_ecc_get_curve_size_from_id(curveId);

    // wc_ecc_make_key_ex(&rng, keySize, &key, curveId);

    // word32 pubSize = 0;
    // byte pubBuf[ECC_BUFSIZE];

    // //1 for compression
    // wc_ecc_export_x963_ex(&key, pubBuf, &pubSize, 0);

    // printf("key2 size: %d\n", pubSize);
    // print_bytes(pubBuf, pubSize);

    // ecc_key readKey;
    // wc_ecc_init(&readKey);

    // wc_ecc_import_x963_ex(pubBuf, pubSize, &readKey, curveId);

    // printf("Import done\n");

    // ecc_key key2;
    // wc_ecc_init(&key2);

    // wc_ecc_make_key_ex(&rng, keySize, &key2, curveId);

    // printf("New key done\n");

    // byte sharedKey[1024];
    // word32 sharedKeySize = sizeof(sharedKey);

    // wc_ecc_shared_secret(&key2, &readKey, sharedKey, &sharedKeySize);

    // printf("Shared: %d\n", sharedKeySize);
    // print_bytes(sharedKey, sharedKeySize);

    // return 0;
}