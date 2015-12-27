#include "function.h"

/**
 *
 */
int bin_to_strhex(unsigned char * bin, unsigned int binsz, unsigned char **result) {
    char hex_str[]= "0123456789abcdef";
    unsigned int  i;

    *result = (unsigned char *)malloc(binsz * 2 + 1);
    (*result)[binsz * 2] = 0;

    if (!binsz) {
        return 1;
    }

    for (i = 0; i < binsz; i++) {
        (*result)[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
        (*result)[i * 2 + 1] = hex_str[(bin[i]     ) & 0x0F];
    }

    return 0;
}
