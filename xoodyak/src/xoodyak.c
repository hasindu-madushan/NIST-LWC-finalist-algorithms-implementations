// 07 Nov 2022
#include "../../utils/hex_utils.h"
#include <stdio.h>
#include <string.h>
#include "xoodoo.h"

#define BLOCK_SIZE 16
 

void xor_block(uint8_t *output, uint8_t *block);
void xor(uint8_t *output, uint8_t *block, uint8_t size);


void encrypt(uint8_t *cipher_text, uint8_t *tag, uint8_t *plain_text, uint32_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
}

uint8_t decrypt(uint8_t *plain_text, uint8_t *tag, uint8_t *cipher_text, uint32_t cipher_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    return 0;
}

void down(uint8_t *state, uint8_t *block, uint8_t color)
{
    xor_block(state, block);
    state[BLOCK_SIZE] ^= 0x01;
    state[STATE_SIZE - 1] ^= color;
}

void up(uint8_t *output, uint8_t out_size, uint8_t *state, uint8_t *block, uint8_t color)
{
    state[STATE_SIZE - 1] ^= color;
    xoodoo(state);
    memcpy(output, state, out_size); 
}

void xor_block(uint8_t *output, uint8_t *block)
{
    xor(output, block, BLOCK_SIZE);
}

void xor(uint8_t *output, uint8_t *block, uint8_t size)
{
    for (uint8_t i = 0; i < size; i++)
	output[i] ^= block[i];
}

int main() 
{
    /* Count = 7
       Key = 000102030405060708090A0B0C0D0E0F
       Nonce = 000102030405060708090A0B0C0D0E0F
       PT = 
       AD = 000102030405
       CT = CE5473EF021AD7853E66C69C56F57167 */


    printf("done!\n");
    return 0;
}
