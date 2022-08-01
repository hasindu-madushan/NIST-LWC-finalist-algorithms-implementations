#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../../utils/hex_utils.h"
#include "spongent.h"


#define BLOCK_SIZE 20 /* block size in bytes */
#define KEY_SIZE 16 /* bytes */

/* Rotate left the 8-bit work b by n */
#define ROTATE_LEFT_8(b, n) (((b) << (n)) | ((b) >> (8 - (n))))

typedef struct 
{
    uint8_t *key;
    uint8_t *nonce;
    uint8_t *associated_data;
    uint8_t *data; /* cipher text or plain text */
} Elephant_data;

uint8_t *encrypt(uint8_t *plain_text, uint32_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    uint8_t i, *cipher_text;
    return cipher_text;
}

void mask(uint8_t *k, uint32_t a, uint32_t b)
{
}

void update_lfsr(uint8_t *output, uint8_t *input)
{
    uint8_t i;
    for (i = 0; i < BLOCK_SIZE - 1; i++)
	output[i] = input[i + 1];
    output[BLOCK_SIZE - 1] = ROTATE_LEFT_8(input[0], 3) ^ (input[3] << 7) ^ (input[19] >> 7);
}

int main() 
{
    char *a_hex = "000102030405060708090A0B0C0D0E0F10111213";
    uint8_t *a = hex_to_bytes(a_hex, 40);
    permute(a);
    printf("%s\n", bytes_to_hex(a, 20));
    return 0;
}
