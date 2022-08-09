#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../../utils/hex_utils.h"
#include "spongent.h"


#define BLOCK_SIZE 20 /* block size in bytes */
#define KEY_SIZE 16 /* bytes */
#define NONCE_SIZE 12

/* Rotate left the 8-bit work b by n */
#define ROTATE_LEFT_8(b, n) (((b) << (n)) | ((b) >> (8 - (n))))

typedef struct 
{
    uint8_t key_padded[BLOCK_SIZE];
    uint8_t *nonce;
    uint8_t *associated_data;
    uint8_t *data; /* cipher text or plain text */
    uint8_t *prev_mask, *current_mask, *next_mask;
    uint8_t mask_buffers[3][BLOCK_SIZE];
} Elephant_data;

void init(Elephant_data *data, uint8_t *key, uint8_t *nonce);
void mask_i_minus_1_1(uint8_t *buffer, Elephant_data *data);
void xor_block(uint8_t *buffer, uint8_t *input);
void update_lfsr(uint8_t *output, uint8_t *input);

uint8_t *encrypt(uint8_t *plain_text, uint32_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    uint8_t i, *cipher_text;
    Elephant_data data;
    uint8_t buffer[BLOCK_SIZE] = {0};

    init(&data, key, nonce);



    update_lfsr(data.next_mask, data.current_mask);

    memcpy(buffer, nonce, NONCE_SIZE);

    mask_i_minus_1_1(buffer, &data);
    permute(buffer);
    mask_i_minus_1_1(buffer, &data);
    xor_block(buffer, plain_text);
    
    printf("cipher text: %s\n", bytes_to_hex(buffer, 20));
    return cipher_text;
}

void init(Elephant_data *data, uint8_t *key, uint8_t *nonce)
{
    memset(data->mask_buffers, 0, 3 * BLOCK_SIZE);
    memcpy(data->key_padded, key, KEY_SIZE);
    memset(data->key_padded + KEY_SIZE, 0, BLOCK_SIZE - KEY_SIZE);
    permute(data->key_padded);

    memcpy(data->mask_buffers[1], data->key_padded, BLOCK_SIZE);
    data->prev_mask = data->mask_buffers[0];
    data->current_mask = data->mask_buffers[1];
    data->next_mask = data->mask_buffers[2];

    data->nonce = nonce;
}

void mask_i_minus_1_1(uint8_t *buffer, Elephant_data *data)
{
    xor_block(buffer, data->current_mask);
    xor_block(buffer, data->next_mask);
}

void xor_block(uint8_t *buffer, uint8_t *input)
{
    uint8_t i;
    for (i = 0; i < BLOCK_SIZE; i++)
	buffer[i] = buffer[i] ^ input[i];
}

void update_lfsr(uint8_t *output, uint8_t *input)
{
    uint8_t i;
    for (i = 0; i < BLOCK_SIZE - 1; i++)
	output[i] = input[i + 1];
    output[BLOCK_SIZE - 1] = ROTATE_LEFT_8(input[0], 3) ^ (input[3] << 7) ^ (input[13] >> 7);
}

int main() 
{
    /* count = 661 */
    char message_hex[] = "000102030405060708090A0B0C0D0E0F10111213";
    char key_hex[] = "000102030405060708090A0B0C0D0E0F";
    char nonce_hex[] = "000102030405060708090A0B";

    uint8_t *message = hex_to_bytes(message_hex, 40);
    uint8_t *key = hex_to_bytes(key_hex, 32);
    uint8_t *nonce = hex_to_bytes(nonce_hex, 24);
    uint8_t *ad;
    
    encrypt(message, 20, key, ad, 0, nonce); 

    return 0;
}
