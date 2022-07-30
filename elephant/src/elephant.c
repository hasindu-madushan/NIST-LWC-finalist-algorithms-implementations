#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../../utils/hex_utils.h"


#define BLOCK_SIZE 20 /* block size in bytes */
#define KEY_SIZE 16 /* bytes */

typedef struct 
{
    uint8_t *key;
    uint8_t *nonce;
    uint8_t *associated_data;
    uint8_t *data; /* cipher text or plain text */
} Elephant_data;

uint8_t i_counter(uint8_t i)
{
    i = (i << 1) | (
}

void x_box_layer()
{
}

int main() 
{
    return 0;
}
