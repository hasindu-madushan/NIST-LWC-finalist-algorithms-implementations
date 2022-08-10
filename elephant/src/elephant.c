#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../../utils/hex_utils.h"
#include "spongent.h"


#define BLOCK_SIZE 20 /* block size in bytes */
#define KEY_SIZE 16 /* bytes */
#define NONCE_SIZE 12
#define TAG_SIZE 8

/* Rotate left the 8-bit work b by n */
#define ROTATE_LEFT_8(b, n) (((b) << (n)) | ((b) >> (8 - (n))))

typedef struct 
{
    uint8_t key_padded[BLOCK_SIZE];
    uint8_t *nonce;
    /* cipher text or plain text */
    uint8_t *message;
    uint32_t message_len;
    uint8_t *associated_data;
    uint32_t adlen;
    uint32_t n_m_blocks;
    uint32_t n_c_blocks;
    uint32_t n_ad_blocks;
    uint8_t *prev_mask, *current_mask, *next_mask;
    uint8_t mask_buffers[3][BLOCK_SIZE];
} Elephant_data;

void encrypt(uint8_t *cipher_text, uint8_t *tag, uint8_t *plain_text, uint32_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce);
void decrypt(uint8_t *plain_text, uint8_t *tag, uint8_t *cipher_text, uint32_t cipher_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce);

void elephat_aead(uint8_t *output, uint8_t *tag, uint8_t *message, uint32_t message_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce, uint8_t encrypt);
void init(Elephant_data *data, uint8_t *key, uint8_t *nonce, uint8_t *plain_text, uint32_t plain_text_len, uint8_t *associated_data, uint32_t adlen);
void process_message_block(uint8_t *cipher_text_block, Elephant_data *data, uint32_t i);
void mask_i_minus_1_1(uint8_t *buffer, Elephant_data *data);
void update_tag_from_a_block(uint8_t *tag, Elephant_data *data, uint32_t index);
void get_a_block(uint8_t *output, Elephant_data *data, uint32_t index);
void mask_i_minus_1_0(uint8_t *buffer, Elephant_data *data);
void update_tag_from_c_block(uint8_t *tag, Elephant_data *data, uint8_t *cipher_text, uint32_t index);
void get_c_block(uint8_t *output, Elephant_data *data, uint8_t *cipher_text, uint32_t index);
void mask_i_minus_1_2(uint8_t *buffer, Elephant_data *data);
void mask_0_0(uint8_t *buffer, Elephant_data *data);
void update_masks(Elephant_data *data);
void xor_block(uint8_t *output, uint8_t *left, uint8_t *right);
void xor_block_partial(uint8_t *output, uint8_t *left, uint8_t *right, uint8_t count);
void update_lfsr(uint8_t *output, uint8_t *input);


void encrypt(uint8_t *cipher_text, uint8_t *tag, uint8_t *plain_text, uint32_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    elephat_aead(cipher_text, tag, plain_text, plain_text_len, key, associated_data, adlen, nonce, 1);
}

void decrypt(uint8_t *plain_text, uint8_t *tag, uint8_t *cipher_text, uint32_t cipher_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    uint8_t tag_decrypt[BLOCK_SIZE]; 
    elephat_aead(plain_text, tag_decrypt, cipher_text, cipher_text_len, key, associated_data, adlen, nonce, 0);
    printf("tag decrypt: %s\n", bytes_to_hex(tag_decrypt, 8));
}

void elephat_aead(uint8_t *output, uint8_t *tag, uint8_t *message, uint32_t message_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce, uint8_t encrypt)
{
    Elephant_data data;
    uint32_t i;

    init(&data, key, nonce, message, message_len, associated_data, adlen);
    get_a_block(tag, &data, 0);
    
    //printf("init tag: %s\n", bytes_to_hex(tag, 20));
     printf("n_c_blocks: %d, n_ad_blocks: %d\n", data.n_c_blocks, data.n_ad_blocks); 
    for (i = 0; i < data.n_c_blocks + 1 || i < data.n_ad_blocks - 1; i++)
    {
	printf("i: %d\n", i);
	update_lfsr(data.next_mask, data.current_mask);
	if (i < data.n_m_blocks)
	    process_message_block(output, &data, i);
	if (i > 0 && i <= data.n_c_blocks) /* start when i = 1 */
	    update_tag_from_c_block(tag, &data, (encrypt ? output : message), i - 1);
	if (i + 1  < data.n_ad_blocks) /* 1 ahead */
	    update_tag_from_a_block(tag, &data, i + 1);
	update_masks(&data);
    }
		
    mask_0_0(tag, &data);
    permute(tag);
    mask_0_0(tag, &data);
}

void init(Elephant_data *data, uint8_t *key, uint8_t *nonce, uint8_t *plain_text, uint32_t plain_text_len, uint8_t *associated_data, uint32_t adlen)
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
    data->message = plain_text;
    data->message_len = plain_text_len;
    data->associated_data = associated_data;
    data->adlen = adlen;
    
    data->n_m_blocks = plain_text_len / BLOCK_SIZE + ((plain_text_len % BLOCK_SIZE) ? 1 : 0);
    data->n_ad_blocks = (NONCE_SIZE + adlen) / BLOCK_SIZE + 1;
    data->n_c_blocks = plain_text_len / BLOCK_SIZE + 1;
}

void process_message_block(uint8_t *cipher_text_block, Elephant_data *data, uint32_t i)
{
    uint8_t buffer[BLOCK_SIZE];
    memcpy(buffer, data->nonce, NONCE_SIZE);
    memset(buffer + NONCE_SIZE, 0, BLOCK_SIZE - NONCE_SIZE);
    mask_i_minus_1_1(buffer, data);
    permute(buffer);
    mask_i_minus_1_1(buffer, data);
    xor_block_partial(cipher_text_block, buffer, data->message + i, data->message_len - i * BLOCK_SIZE); 
}

void mask_i_minus_1_1(uint8_t *buffer, Elephant_data *data)
{
    xor_block(buffer, buffer, data->current_mask);
    xor_block(buffer, buffer, data->next_mask);
}

void update_tag_from_a_block(uint8_t *tag, Elephant_data *data, uint32_t index)
{
    uint8_t buffer[BLOCK_SIZE];
    get_a_block(buffer, data, index);
    mask_i_minus_1_0(buffer, data);
    permute(buffer);
    mask_i_minus_1_0(buffer, data);
    xor_block(tag, tag, buffer);
}

void get_a_block(uint8_t *output, Elephant_data *data, uint32_t index)
{
    uint32_t offset, count, start;
    start = 0;
    if (index == 0)
    {
	memcpy(output, data->nonce, NONCE_SIZE);
	start = NONCE_SIZE;
    }

    offset = index * BLOCK_SIZE - (index > 0 ? NONCE_SIZE : 0);
    count = (data->adlen - offset < BLOCK_SIZE - start) ? (data->adlen - offset) : (BLOCK_SIZE - start);
    printf("get_c_block | count: %d, offset: %d\n", count, offset);
    memcpy(output + start, data->associated_data + offset, count);
    if (count < BLOCK_SIZE - start)
    {
	output[start + count] = 0x01;
	memset(start + output + count + 1, 0, BLOCK_SIZE - start - count - 1);
    }
    printf("A[%d]: %s\n", index, bytes_to_hex(output, 20));
}

void mask_i_minus_1_0(uint8_t *buffer, Elephant_data *data)
{
    xor_block(buffer, buffer, data->next_mask);
}

void update_tag_from_c_block(uint8_t *tag, Elephant_data *data, uint8_t *cipher_text, uint32_t index)
{
    uint8_t buffer[BLOCK_SIZE];
    get_c_block(buffer, data, cipher_text, index);
    mask_i_minus_1_2(buffer, data);
    permute(buffer);
    mask_i_minus_1_2(buffer, data);
    xor_block(tag, tag, buffer);
}

void get_c_block(uint8_t *output, Elephant_data *data, uint8_t *cipher_text, uint32_t index)
{
    uint32_t offset, count;
    offset = index * BLOCK_SIZE;
    count = ((data->message_len - offset) < BLOCK_SIZE) ? (data->message_len - offset) : BLOCK_SIZE;
    memcpy(output, cipher_text + offset, count);
    printf("get_c_block | count: %d, offset: %d\n", count, offset);
    if (count < BLOCK_SIZE)
    {
	output[count] = 0x01;
	memset(output + count + 1, 0, BLOCK_SIZE - count - 1);
    }
    printf("C[%d]: %s\n", index, bytes_to_hex(output, 20));
}

void mask_i_minus_1_2(uint8_t *buffer, Elephant_data *data)
{
    xor_block(buffer, buffer, data->prev_mask);
    xor_block(buffer, buffer, data->next_mask);
}

void update_masks(Elephant_data *data)
{
    uint8_t* temp;
    temp = data->prev_mask;
    data->prev_mask = data->current_mask;
    data->current_mask = data->next_mask;
    data->next_mask = temp;
}

void mask_0_0(uint8_t *buffer, Elephant_data *data)
{
    xor_block(buffer, buffer, data->key_padded);
}

void xor_block(uint8_t *output, uint8_t *left, uint8_t *right)
{
    xor_block_partial(output, left, right, BLOCK_SIZE);
}

void xor_block_partial(uint8_t *output, uint8_t *left, uint8_t *right, uint8_t count)
{
    uint8_t i;
    for (i = 0; i < count; i++)
	output[i] = left[i] ^ right[i];
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
    /* count = 101 */
    char message_hex[] = "000102";
    char ad_hex[] = "00";

    char key_hex[] = "000102030405060708090A0B0C0D0E0F";
    char nonce_hex[] = "000102030405060708090A0B";

    uint8_t *message = hex_to_bytes(message_hex, sizeof(message_hex));
    uint32_t message_len = sizeof(message_hex) / 2;
    uint8_t *key = hex_to_bytes(key_hex, 32);
    uint8_t *nonce = hex_to_bytes(nonce_hex, 24);
    uint8_t *ad = hex_to_bytes(ad_hex, sizeof(ad_hex));
    uint32_t adlen = sizeof(ad_hex) / 2;

    uint8_t *cipher_text = (uint8_t*)malloc(message_len);
    uint8_t tag[20];

    encrypt(cipher_text, tag, message, message_len, key, ad, adlen, nonce); 

    printf("cipher_text: %s\n", bytes_to_hex(cipher_text, message_len));
    printf("tag: %s\n", bytes_to_hex(tag, 8));

    uint8_t *plaint_text = (uint8_t*)malloc(message_len);
    decrypt(plaint_text, tag, cipher_text, message_len, key, ad, adlen, nonce);
    printf("decryptted plain text: %s\n", bytes_to_hex(plaint_text, message_len));

    free(cipher_text);
    free(plaint_text);

    printf("done!\n");
    return 0;
}
