// 07 Nov 2022
#include "../../utils/hex_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "xoodoo.h"

#define KEY_SIZE 16
#define NONCE_SIZE 16 
#define TAG_SIZE 16

#define R_KOUT 16
#define R_KIN 44
#define L_RATCHET 16
#define R_HASH 16


#define MIN(a, b) ((a) < (b) ? (a) : (b))

typedef enum  
{
    PHASE_UP,
    PHASE_DOWN 
} Phase;

typedef struct
{
    uint8_t state[STATE_SIZE];
    uint8_t *key;
    Phase phase;
    uint16_t r_absorb;
    uint16_t r_squeeze;
} Xoodyak_data;

void init_xoodyak_data(Xoodyak_data *xoodyak_data, uint8_t *key);
void cyclist(Xoodyak_data* xoodyak_data, uint8_t *id, uint8_t id_len, uint8_t *counter, uint32_t counter_len);
void crypt(uint8_t *output, uint8_t *data, uint32_t data_len, Xoodyak_data *xoodyak_data, uint8_t decrypt);
void absorb(Xoodyak_data *xoodyak_data, uint8_t *data, uint32_t data_len);
void squeeze(uint8_t *output, uint32_t out_size, Xoodyak_data *xoodyak_data);

void absorb_any(Xoodyak_data *xoodyak_data, uint8_t *data, uint32_t data_len, uint8_t rate, uint8_t color);
void squeeze_any(uint8_t *output, uint32_t out_size, Xoodyak_data *xoodyak_data, uint8_t color);
void absorb_key(Xoodyak_data *xoodyak_data, uint8_t *id, uint8_t id_len, uint8_t *counter, uint32_t counter_len);

void down(Xoodyak_data *xoodyak_data, uint8_t *data, uint32_t data_len, uint8_t color);
void up(uint8_t *output, uint8_t out_size, Xoodyak_data *xoodyak_data, uint8_t color);

void xor(uint8_t *output, uint8_t *block, uint8_t size);
void xor2(uint8_t *output, uint8_t *left, uint8_t *right, uint8_t size);


void encrypt(uint8_t *cipher_text, uint8_t *tag, uint8_t *plain_text, uint32_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    Xoodyak_data xoodyak_data;
    init_xoodyak_data(&xoodyak_data, key);
    cyclist(&xoodyak_data, nonce, NONCE_SIZE, NULL, 0);
    printf("cyclist: %s\n", bytes_to_hex(xoodyak_data.state, STATE_SIZE));
//    absorb(&xoodyak_data, nonce, NONCE_SIZE);
    printf("absorb nonce\n");
    absorb(&xoodyak_data, associated_data, adlen);
    printf("absorb ad %s\n", bytes_to_hex(xoodyak_data.state, STATE_SIZE));
    crypt(cipher_text, plain_text, plain_text_len, &xoodyak_data, 0);
    printf("crypt: %s\n", bytes_to_hex(xoodyak_data.state, STATE_SIZE));
    squeeze(tag, TAG_SIZE, &xoodyak_data);
}

uint8_t decrypt(uint8_t *plain_text, uint8_t *tag, uint8_t *cipher_text, uint32_t cipher_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    Xoodyak_data xoodyak_data;
    uint8_t tag_[TAG_SIZE];
    init_xoodyak_data(&xoodyak_data, key);
    cyclist(&xoodyak_data, nonce, NONCE_SIZE, NULL, 0);
    absorb(&xoodyak_data, associated_data, adlen);
    crypt(plain_text, cipher_text, cipher_text_len, &xoodyak_data, 1);
    squeeze(tag_, TAG_SIZE, &xoodyak_data);
    
    printf("tag_: %s\n", bytes_to_hex(tag_, 16));
    uint8_t tag_matches = 1;

    for (uint8_t i = 0; i < TAG_SIZE; i++)
	if (tag[i] != tag_[i])
	    tag_matches = 0;

    if (!tag_matches)
	memset(plain_text, 0, cipher_text_len);

    return tag_matches;
}

void init_xoodyak_data(Xoodyak_data *xoodyak_data, uint8_t *key)
{
    xoodyak_data->key = key;
}

void cyclist(Xoodyak_data* xoodyak_data, uint8_t *id, uint8_t id_len, uint8_t *counter, uint32_t counter_len)
{
    xoodyak_data->phase = PHASE_UP;
    memset(xoodyak_data->state, 0, STATE_SIZE);
    absorb_key(xoodyak_data, id, id_len, counter, counter_len);
}

void absorb_key(Xoodyak_data *xoodyak_data, uint8_t *id, uint8_t id_len, uint8_t *counter, uint32_t counter_len)
{
    xoodyak_data->r_absorb = R_KIN;
    xoodyak_data->r_squeeze = R_KOUT;

    uint8_t *buffer = malloc(KEY_SIZE + id_len + 1); 
    memcpy(buffer, xoodyak_data->key, KEY_SIZE);
    memcpy(buffer + KEY_SIZE, id, id_len);
    buffer[KEY_SIZE + id_len] = id_len;
    absorb_any(xoodyak_data, buffer, KEY_SIZE + id_len + 1, xoodyak_data->r_absorb, 0x02);

    if (counter_len > 0)
	absorb_any(xoodyak_data, counter, counter_len, 1, 0x00);

    free(buffer);
}

void absorb_any(Xoodyak_data *xoodyak_data, uint8_t *data, uint32_t data_len, uint8_t rate, uint8_t color)
{
    uint32_t current_size = 0;

    while (current_size < data_len)
    {
	uint32_t len = MIN(data_len - current_size, rate);
	if (xoodyak_data->phase != PHASE_UP)
	    up(NULL, 0, xoodyak_data, 0x00);
	down(xoodyak_data, data + current_size, len, current_size == 0 ? color : 0x00);
	current_size += len;
    }
}

void absorb(Xoodyak_data *xoodyak_data, uint8_t *data, uint32_t data_len)
{
    absorb_any(xoodyak_data, data, data_len, xoodyak_data->r_absorb, 0x03);
}

void squeeze(uint8_t *output, uint32_t out_size, Xoodyak_data *xoodyak_data)
{
    squeeze_any(output, out_size, xoodyak_data, 0x40);
}

void ratchet(Xoodyak_data *xoodyak_data)
{
    uint8_t x[L_RATCHET];
    squeeze_any(x, L_RATCHET, xoodyak_data, 0x10);
    absorb_any(xoodyak_data, x, L_RATCHET, xoodyak_data->r_absorb, 0x00);
}

void crypt(uint8_t *output, uint8_t *data, uint32_t data_len, Xoodyak_data *xoodyak_data, uint8_t decrypt)
{
    uint32_t current_size = 0;
    uint8_t p[R_KOUT];

    do {
	uint8_t len = MIN(data_len - current_size, R_KOUT);
	up(p, len, xoodyak_data, current_size > 0 ? 0x00 : 0x80);
	xor2(output + current_size, data + current_size, p, len);
	memcpy(p, (decrypt ? output : data) + current_size, len);
	down(xoodyak_data, p, len, 0x00);
	current_size += len;
    } while (current_size < data_len);
}

void squeeze_any(uint8_t *output, uint32_t out_size, Xoodyak_data *xoodyak_data, uint8_t color)
{
    uint32_t current_size =  MIN(out_size, xoodyak_data->r_squeeze); 
    up(output, current_size, xoodyak_data, color);

    while (current_size < out_size)
    {
	down(xoodyak_data, NULL, 0, 0x00);
	uint32_t len = MIN(out_size - current_size, xoodyak_data->r_squeeze);
	up(output + current_size, len, xoodyak_data, 0x00);
	current_size += len;
    }
}

void down(Xoodyak_data *xoodyak_data, uint8_t *data, uint32_t data_len, uint8_t color)
{
    xoodyak_data->phase = PHASE_DOWN;
    xor(xoodyak_data->state, data, data_len);
    xoodyak_data->state[data_len] ^= 0x01;
    xoodyak_data->state[STATE_SIZE - 1] ^= color;
}

void up(uint8_t *output, uint8_t out_size, Xoodyak_data *xoodyak_data, uint8_t color)
{
    xoodyak_data->phase = PHASE_UP;
    xoodyak_data->state[STATE_SIZE - 1] ^= color;
    xoodoo(xoodyak_data->state);
    memcpy(output, xoodyak_data->state, out_size); 
}

void xor(uint8_t *output, uint8_t *block, uint8_t size)
{
    xor2(output, output, block, size);
}

void xor2(uint8_t *output, uint8_t *left, uint8_t *right, uint8_t size)
{
    for (uint8_t i = 0; i < size; i++)
	output[i] = left[i] ^ right[i];
}

int main() 
{
    /* Count = 39 */
    char key_hex[] = "000102030405060708090A0B0C0D0E0F";
    char nonce_hex[] = "000102030405060708090A0B0C0D0E0F";
    char message_hex[]  = "0001";
    char ad_hex[] = "00010203";
    /* CT = "CE5473EF021AD7853E66C69C56F57167"; */

    uint8_t *message = hex_to_bytes(message_hex, sizeof(message_hex));
    uint32_t message_len = sizeof(message_hex) / 2;
    uint8_t *key = hex_to_bytes(key_hex, KEY_SIZE * 2);
    uint8_t *nonce = hex_to_bytes(nonce_hex, NONCE_SIZE * 2);
    uint8_t *ad = hex_to_bytes(ad_hex, sizeof(ad_hex));
    uint32_t adlen = sizeof(ad_hex) / 2;

    uint8_t *cipher_text = (uint8_t*)malloc(message_len);
    uint8_t tag[20];
    uint8_t *decrypted_plaintext = malloc(message_len);

    printf("message %s, ad %s\n", bytes_to_hex(message, message_len), bytes_to_hex(ad, adlen));
    encrypt(cipher_text, tag, message, message_len, key, ad, adlen, nonce); 

    printf("cipher_text: %s\n", bytes_to_hex(cipher_text, message_len));
    printf("tag: %s\n", bytes_to_hex(tag, 16));

    uint8_t tag_matches = decrypt(decrypted_plaintext, tag, cipher_text, message_len, key, ad, adlen, nonce);
    printf("decrypted plain text: %s\n", bytes_to_hex(decrypted_plaintext, message_len));
    printf("tag matches = %d\n", tag_matches);

    printf("done!\n");
    return 0;
}
