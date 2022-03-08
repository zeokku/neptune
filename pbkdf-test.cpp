/*
g++ -o pbkdf debug.cpp pbkdf-test.cpp -lssl -lcrypto && ./pbkdf
*/

#include <openssl/evp.h>
#include <string.h>

#include "./debug.h"

typedef unsigned char byte;

int main()
{

    byte output[32];
    byte *salt = (byte *)"salt";

    char pwd1[] = {0};
    PKCS5_PBKDF2_HMAC(pwd1, sizeof(pwd1), salt, 4, 100000, EVP_sha256(), 32, output);
    print_bytes(output, 32);

    memset(output, 0, sizeof(output));

    char pwd2[] = {0, 0};
    PKCS5_PBKDF2_HMAC(pwd2, sizeof(pwd2), salt, 4, 100000, EVP_sha256(), 32, output);
    print_bytes(output, 32);

    return 0;
}