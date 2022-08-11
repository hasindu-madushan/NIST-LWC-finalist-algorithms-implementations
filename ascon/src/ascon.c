#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ascon_permutation.h"
#include "../../utils/hex_utils.h"


#define KEY_SIZE 16
#define NONCE_SIZE 16
#define TAG_SIZE 16
#define BLOCK_SIZE 8
#define STATE_SIZE 40

#define S(i) (data->state[i])

typedef struct
{
    uint64_t key[2];
    uint64_t nonce[2];
    uint8_t *message;
    uint32_t message_len;
    uint8_t *associated_data;
    uint32_t adlen;
    uint64_t state[5];
} Ascon_data;

void get_block_padded(uint8_t *output, uint8_t *data, uint32_t data_len, uint32_t index);
void init_data(Ascon_data *data, uint8_t *message, uint32_t message_len, uint8_t *associated_data, uint32_t adlen, uint8_t *key, uint8_t *nonce);
void initialize_state(Ascon_data *data);
void process_associated_data(Ascon_data *data);
void process_plain_text(uint8_t *cipher_text, Ascon_data *data);
void load_bytes_output_reversed(uint8_t* output, uint8_t output_offset, uint8_t* input, uint8_t count);
void load_bytes_input_reversed(uint8_t *output, uint8_t *input, uint8_t count);


void encrypt(uint8_t *cipher_text, uint8_t *tag, uint8_t *plain_text, uint32_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    Ascon_data data;
    init_data(&data, plain_text, plain_text_len, associated_data, adlen, key, nonce);
    initialize_state(&data);
    printf("state after init: %s\n", bytes_to_hex((uint8_t*)data.state, STATE_SIZE));
    process_associated_data(&data);
    printf("state after process ad: %s\n", bytes_to_hex((uint8_t*)data.state, STATE_SIZE));
    process_plain_text(cipher_text, &data);
}

void init_data(Ascon_data *data, uint8_t *message, uint32_t message_len, uint8_t *associated_data, uint32_t adlen, uint8_t *key, uint8_t *nonce)
{
    data->message = message;
    data->message_len = message_len;
    data->associated_data = associated_data;
    data->adlen = adlen;
    load_bytes_output_reversed((uint8_t*)data->key, 0, key, 8);
    load_bytes_output_reversed((uint8_t*)&data->key[1], 0, key + 8, 8);
    load_bytes_output_reversed((uint8_t*)data->nonce, 0, nonce, 8);
    load_bytes_output_reversed((uint8_t*)&data->nonce[1], 0, nonce + 8, 8);
}

void initialize_state(Ascon_data *data)
{
    data->state[0] = 0x80400c0600000000;

    data->state[1] = data->key[0];
    data->state[2] = data->key[1];
    data->state[3] = data->nonce[0];
    data->state[4] = data->nonce[1];

    printf("state before init perm: %s\n", bytes_to_hex((uint8_t*)data->state, STATE_SIZE));
    permute_a(data->state);
    printf("state after init perm: %s\n", bytes_to_hex((uint8_t*)data->state, STATE_SIZE));

    data->state[3] ^= data->key[0];
    data->state[4] ^= data->key[1];
}

void process_associated_data(Ascon_data *data)
{
    uint64_t temp;
    uint32_t n_ad_blocks, i;
    if (data->adlen > 0)
    {
	n_ad_blocks = data->adlen / BLOCK_SIZE + 1;
	for (i = 0; i < n_ad_blocks; i++) 
	{
	    get_block_padded((uint8_t*)&temp, data->associated_data, data->adlen, i);		
	    printf("ad block %d: %s\n", i, bytes_to_hex((uint8_t*)&temp, 8));
	    data->state[0] ^= temp;
	    permute_b(data->state);
	}
    }
    data->state[4] ^= 0x01;
}

void process_plain_text(uint8_t *cipher_text, Ascon_data *data)
{
    uint64_t temp;
    uint32_t n_message_blocks, i;
    n_message_blocks = data->message_len / BLOCK_SIZE + 1;
    for (i = 0; i < n_message_blocks - 1; i++)
    {
	get_block_padded((uint8_t*)&temp, data->message, data->message_len, i);
	data->state[0] ^= temp;
	cipher_text[i] = data->state[0];
	load_bytes_input_reversed((uint8_t*)((uint64_t*)cipher_text + i), (uint8_t*)data->state, BLOCK_SIZE);
	permute_b(data->state);
    }
    get_block_padded((uint8_t*)&temp, data->message, data->message_len, n_message_blocks - 1);
    data->state[0] ^= temp;
    printf("s[0]: %s\n", bytes_to_hex((uint8_t*)data->state, 8));
    load_bytes_input_reversed((uint8_t*)((uint64_t*)cipher_text + n_message_blocks - 1), (uint8_t*)data->state, data->message_len % BLOCK_SIZE);
} 
    
/**
 * Returns a index th block of data. Pladded with 1 || 0 *. For plain text, ad or 
 * cipher text.
 */
void get_block_padded(uint8_t *output, uint8_t *data, uint32_t data_len, uint32_t index)
{
    uint32_t offset, count;
    offset = index * BLOCK_SIZE;
    count = ((data_len - offset) < BLOCK_SIZE) ? (data_len - offset) : BLOCK_SIZE;
    //memcpy(output, data + offset, count);
    load_bytes_output_reversed(output, 0, data + offset, count);
    printf("count: %d\n", count);
    if (count < BLOCK_SIZE)
    {
	output[BLOCK_SIZE - count - 1] = 0x80;
	memset(output, 0, BLOCK_SIZE - count - 1);
    }
}
    
void load_bytes_output_reversed(uint8_t* output, uint8_t output_offset, uint8_t* input, uint8_t count)
{
    uint8_t i;
    output_offset = BLOCK_SIZE - output_offset - 1;
    for (i = 0; i < count; i++)
	output[output_offset - i] = input[i];
}

void load_bytes_input_reversed(uint8_t *output, uint8_t *input, uint8_t count)
{
    uint8_t i;
    for (i = 0; i < count; i++)
	output[i] = input[BLOCK_SIZE - i - 1];
}

int main() {
    /* count = 624 */
    char message_hex[] = "000102030405060708090A0B0C0D0E0F1011";
    char ad_hex[] = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C";

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
    //printf("tag: %s\n", bytes_to_hex(tag, 8));

    uint8_t *plaint_text = (uint8_t*)malloc(message_len);
    //uint8_t verify = decrypt(plaint_text, tag, cipher_text, message_len, key, ad, adlen, nonce);
    //printf("decryptted plain text: %s\n", bytes_to_hex(plaint_text, message_len));
    //printf("tag verify: %d\n", verify);

    free(cipher_text);
    free(plaint_text);

    printf("done!\n");
    return 0;
}
