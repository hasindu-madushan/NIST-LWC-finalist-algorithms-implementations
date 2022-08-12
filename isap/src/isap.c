/* ISAP-A-128 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "../../ascon/src/ascon_permutation.h"
#include "../../utils/hex_utils.h"
#include <stdio.h>


#define KEY_SIZE 16
#define STATE_SIZE 40
#define BLOCK_SIZE 8
#define NONCE_SIZE 16
#define ROUNDS_H 12 
#define ROUNDS_B 12 
#define ROUNDS_E 12
#define ROUNDS_K 12 
#define IV_SIZE 8

typedef struct
{
    uint8_t *key;
    uint8_t *nonce;
    uint8_t *message;
    uint32_t message_len;
    uint8_t *associated_data;
    uint32_t adlen;
} Isap_data;

const uint8_t IV_KE[] = {0x03, 128, 64, 1, 12, 12, 12, 12};

void isap_enc(uint8_t *cipher_text, Isap_data *data);
void isap_rk_enc(uint8_t *output, uint8_t *key, uint8_t *input);
void init_data(Isap_data *data, uint8_t *message, uint32_t message_len, uint8_t *associated_data, uint32_t adlen, uint8_t *key, uint8_t *nonce);
void permute(uint64_t *state);
void load_state_reversed(uint64_t *output, uint64_t *state);
void load_reversed_64(uint8_t *output, uint8_t *input);
void xor_block(uint8_t *output, uint8_t *left, uint8_t *right, uint8_t count);


void encrypt(uint8_t *cipher_text, uint8_t *tag, uint8_t *plain_text, uint32_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    Isap_data data;
    init_data(&data, plain_text, plain_text_len, associated_data, adlen, key, nonce);
    isap_enc(cipher_text, &data);
}

void init_data(Isap_data *data, uint8_t *message, uint32_t message_len, uint8_t *associated_data, uint32_t adlen, uint8_t *key, uint8_t *nonce)
{
    data->message = message;
    data->message_len = message_len;
    data->associated_data = associated_data;
    data->adlen = adlen;
    data->key = key;
    data->nonce = nonce;
}

void isap_enc(uint8_t *cipher_text, Isap_data *data)
{
    uint64_t state[5];
    uint32_t i, n_message_blocks;
    uint8_t offset;
    isap_rk_enc((uint8_t*)state, data->key, data->nonce);
    memcpy((uint8_t*)state + STATE_SIZE - NONCE_SIZE, data->nonce, NONCE_SIZE);
    printf("state after rk: %s\n", bytes_to_hex((uint8_t*)state, 40));

    n_message_blocks = data->message_len / BLOCK_SIZE + (data->message_len % BLOCK_SIZE ? 1 : 0);

    for (i = 0; i < n_message_blocks - 1; i++)
    {
	permute(state);
	*(uint64_t*)(cipher_text + i) = *(uint64_t*)data->message ^ state[0];
    }
    
    offset = (n_message_blocks - 1) * BLOCK_SIZE;
    permute(state);
    xor_block(cipher_text + offset, data->message + offset, (uint8_t*)state, data->message_len % BLOCK_SIZE); /* Optimize % */

}

void isap_rk_enc(uint8_t *output, uint8_t *key, uint8_t *input)
{
    uint64_t state[5];
    uint8_t i, j, current_bit;
    memcpy(state, key, KEY_SIZE);
    //load_reversed_64((uint8_t*)state, key);
    //load_reversed_64((uint8_t*)(state + 1), key + 8);
    memcpy(state + 2, IV_KE, IV_SIZE);
    //load_reversed_64((uint8_t*)(state + 2), (uint8_t*)IV_KE);
    state[3] = 0; 
    state[4] = 0;
    printf("state before perm rk: %s\n", bytes_to_hex((uint8_t*)state, 40));
    permute(state);
    printf("state after perm rk: %s\n", bytes_to_hex((uint8_t*)state, 40));

    for (i = 0; i < NONCE_SIZE; i++)
    {
	for (j = 0; j < 8; j++)
	{
	    current_bit = (input[i] << j) & 0x80; 
	    //printf("bit %d: %d\n", i * 8 + j, current_bit > 0);
	    *(uint8_t*)state ^= current_bit;
	    //printf("state: %s\n", bytes_to_hex((uint8_t*)state, 40));
	    permute(state);
	    //printf("state: %s\n", bytes_to_hex((uint8_t*)state, 40));

	}
    }

    memcpy(output, state, STATE_SIZE - NONCE_SIZE);
}

void isap_mac(uint8_t *tag, Isap_data *data)
{
}

void permute(uint64_t *state)
{
    uint64_t state_reversed[5];
    load_state_reversed(state_reversed, state);
    permute_a(state_reversed);
    load_state_reversed(state, state_reversed);
}

void load_state_reversed(uint64_t *output, uint64_t *state)
{
    load_reversed_64((uint8_t*)output, (uint8_t*)state);
    load_reversed_64((uint8_t*)(output + 1), (uint8_t*)(state + 1));
    load_reversed_64((uint8_t*)(output + 2), (uint8_t*)(state + 2));
    load_reversed_64((uint8_t*)(output + 3), (uint8_t*)(state + 3));
    load_reversed_64((uint8_t*)(output + 4), (uint8_t*)(state + 4));
}

void load_reversed_64(uint8_t *output, uint8_t *input)
{
    output[0] = input[7];
    output[1] = input[6];
    output[2] = input[5];
    output[3] = input[4];
    output[4] = input[3];
    output[5] = input[2];
    output[6] = input[1];
    output[7] = input[0];
}

void xor_block(uint8_t *output, uint8_t *left, uint8_t *right, uint8_t count)
{
    uint8_t i;
    for (i = 0; i < count; i++)
	output[i] = left[i] ^ right[i];
}

int main() {
    /* count = 195 */
    char message_hex[] = "000102";
    char ad_hex[] = "00";

    char key_hex[] = "000102030405060708090A0B0C0D0E0F";
    char nonce_hex[] = "000102030405060708090A0B0C0D0E0F";

    uint8_t *message = hex_to_bytes(message_hex, sizeof(message_hex));
    uint32_t message_len = sizeof(message_hex) / 2;
    uint8_t *key = hex_to_bytes(key_hex, KEY_SIZE * 2);
    uint8_t *nonce = hex_to_bytes(nonce_hex, NONCE_SIZE * 2);
    uint8_t *ad = hex_to_bytes(ad_hex, sizeof(ad_hex));
    uint32_t adlen = sizeof(ad_hex) / 2;

    uint8_t *cipher_text = (uint8_t*)malloc(message_len);
    uint8_t tag[20];

    encrypt(cipher_text, tag, message, message_len, key, ad, adlen, nonce); 

    printf("cipher_text: %s\n", bytes_to_hex(cipher_text, message_len));
    //printf("tag: %s\n", bytes_to_hex(tag, 16));

    uint8_t *plaint_text = (uint8_t*)malloc(message_len);
    //uint8_t verify = decrypt(plaint_text, tag, cipher_text, message_len, key, ad, adlen, nonce);
    //printf("decryptted plain text: %s\n", bytes_to_hex(plaint_text, message_len));
    //printf("tag verify: %d\n", verify);

    free(cipher_text);
    free(plaint_text);

    printf("done!\n");
    return 0;
}
