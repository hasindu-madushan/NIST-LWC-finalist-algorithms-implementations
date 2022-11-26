// 07 Nov 2022
#include "../../utils/hex_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "xoodoo.h"

#define BLOCK_SIZE 16
#define KEY_SIZE 16
#define NONCE_SIZE 16 

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

void absorb_any(Xoodyak_data *xoodyak_data, uint8_t *data, uint32_t data_len, uint8_t rate, uint8_t color);
void squeeze_any(uint8_t *output, uint32_t out_size, Xoodyak_data *xoodyak_data, uint8_t color);
void absorb_key(Xoodyak_data *xoodyak_data, uint8_t *id, uint8_t id_len, uint8_t *counter, uint32_t counter_len);

void down(uint8_t *state, uint8_t *block, uint32_t len, uint8_t color);
void up(uint8_t *output, uint8_t out_size, Xoodyak_data *xoodyak_data, uint8_t color);

void xor(uint8_t *output, uint8_t *block, uint8_t size);
void xor2(uint8_t *output, uint8_t *left, uint8_t *right, uint8_t size);


void encrypt(uint8_t *cipher_text, uint8_t *tag, uint8_t *plain_text, uint32_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    Xoodyak_data xoodyak_data;
    init_xoodyak_data(&xoodyak_data, key);
    cyclist(&xoodyak_data, NULL, 0, NULL, 0);
    absorb(&xoodyak_data, nonce, NONCE_SIZE);
    absorb(&xoodyak_data, associated_data, adlen);
    crypt(cipher_text, plain_text, plain_text_len, &xoodyak_data, 0);
}

uint8_t decrypt(uint8_t *plain_text, uint8_t *tag, uint8_t *cipher_text, uint32_t cipher_text_len, uint8_t *key, uint8_t *associated_data, uint32_t adlen, uint8_t *nonce)
{
    return 0;
}

void init_xoodyak_data(Xoodyak_data *xoodyak_data, uint8_t *key)
{
    xoodyak_data->key = key;
    xoodyak_data->r_absorb = R_HASH;
    xoodyak_data->r_squeeze = R_HASH;
}


void cyclist(Xoodyak_data* xoodyak_data, uint8_t *id, uint8_t id_len, uint8_t *counter, uint32_t counter_len)
{
    xoodyak_data->phase = PHASE_UP;
    memset(xoodyak_data->state, 0, STATE_SIZE);
    absorb_key(xoodyak_data, id, id_len, counter, counter_len);
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

void absorb_key(Xoodyak_data *xoodyak_data, uint8_t *id, uint8_t id_len, uint8_t *counter, uint32_t counter_len)
{
    xoodyak_data->r_absorb = R_KIN;
    xoodyak_data->r_squeeze = R_KOUT;

    uint8_t *x = malloc(KEY_SIZE + id_len + 1); 
    memcpy(x, xoodyak_data->key, KEY_SIZE);
    memcpy(x + KEY_SIZE, id, id_len);
    x[KEY_SIZE + id_len] = id_len;
    absorb_any(xoodyak_data, x, KEY_SIZE + id_len + 1, xoodyak_data->r_absorb, 0x02);

    if (counter_len > 0)
	absorb_any(xoodyak_data, counter, counter_len, 1, 0x00);
}

void absorb_any(Xoodyak_data *xoodyak_data, uint8_t *data, uint32_t data_len, uint8_t rate, uint8_t color)
{
    uint32_t current_size = 0;
    while (current_size < data_len)
    {
	uint32_t len = MIN(data_len - current_size, rate);
	if (xoodyak_data->phase != PHASE_UP)
	    up(NULL, 0, xoodyak_data, 0x00);
	down(xoodyak_data->state, data + current_size, len, current_size == 0 ? color : 0x00);
	current_size += len;
    }
}

void crypt(uint8_t *output, uint8_t *data, uint32_t data_len, Xoodyak_data *xoodyak_data, uint8_t decrypt)
{
    uint32_t current_size = 0;
    uint8_t p[R_KOUT];
    while (current_size < data_len)
    {
	uint8_t len = MIN(data_len - current_size, R_KOUT);
	up(p, len, xoodyak_data, current_size > 0 ? 0x00 : 0x80);
	xor2(output + current_size, data + current_size, p, len);
	memcpy(p, (decrypt ? output : data) + current_size, len);
	down(xoodyak_data->state, p, len, 0x00);
    }
}

void squeeze_any(uint8_t *output, uint32_t out_size, Xoodyak_data *xoodyak_data, uint8_t color)
{
    uint32_t current_size = 0; 
    up(output, MIN(out_size, xoodyak_data->r_squeeze), xoodyak_data, color);
    while (current_size < out_size)
    {
	uint32_t len = MIN(out_size - current_size, xoodyak_data->r_squeeze);
	up(output + current_size, len, xoodyak_data, 0x00);
	current_size += len;
    }
}

void down(uint8_t *state, uint8_t *block, uint32_t len, uint8_t color)
{
    xor(state, block, len);
    state[len] ^= 0x01;
    state[STATE_SIZE - 1] ^= color;
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
    /* Count = 7
       Key = 000102030405060708090A0B0C0D0E0F
       Nonce = 000102030405060708090A0B0C0D0E0F
       PT = 
       AD = 000102030405
       CT = CE5473EF021AD7853E66C69C56F57167 */


    printf("done!\n");
    return 0;
}
