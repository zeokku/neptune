typedef unsigned char byte;

#include <iostream>

void print_bytes(byte *arr, size_t size)
{
    for (size_t e = 0; e < size; e += 1)
    {
        printf("%02X%s", arr[e], e % 32 == 31 ? "\n" : " ");
    }

    printf("\n");
}