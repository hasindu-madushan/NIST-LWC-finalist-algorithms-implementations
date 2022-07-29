#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../../utils/hex_utils.h"
#include "gift128.h"

/* First half of the G(Y) */
#define G_0(y) y[1] 
/* Second half of the G(Y) */
#define G_1(y) (((y)[0] << 1) | ((y)[0] >> 63))

#define ROTATE_LEFT_64(w, n) (((w) << (n)) | ((w) >> (64 - (n))))

uint8_t *encrypt(uint8_t *plain_text, uint64_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint64_t adlen, uint8_t *nonce);

void triple_half_block(uint8_t* d, uint8_t* s);
void double_half_block(uint8_t* d, uint8_t* s);
void process_associated_data(uint64_t *y, uint64_t *x, uint8_t *associated_data, uint64_t adlen, uint32_t a, uint8_t *key, uint64_t *L);
void process_ad_block(uint64_t *y, uint64_t *x, uint64_t *associated_data, uint8_t *key, uint32_t j, uint64_t *L);
void process_plain_text(uint8_t *cipher_text, uint64_t *y, uint64_t *x, uint8_t *plain_text, uint64_t plain_text_len, uint8_t *key, uint64_t *L, uint32_t a, uint32_t m);
void process_plain_text_block(uint8_t *cipher_text, uint64_t *y, uint64_t *x, uint64_t *plain_text_block, uint8_t *key, uint32_t j, uint64_t *L, uint32_t a);
void pad(uint8_t *result, uint8_t *block, uint32_t len);

uint64_t rotate_left_64(uint8_t *x)
{
    uint8_t res[8], i;
    for (i = 0; i < 7; i++)
	res[i] = x[i] << 1 | x[i + 1] >> 7;
    res[7] = x[7] << 1 | x[0] >> 7;
    return *(uint64_t*)&res;
}

uint8_t *encrypt(uint8_t *plain_text, uint64_t plain_text_len, uint8_t *key, uint8_t *associated_data, uint64_t adlen, uint8_t *nonce)
{
    uint32_t a, m, i, j, k;
    uint64_t *y, *x, last_block[2];
    uint64_t L;
    uint8_t *cipher_text;
    a = (adlen >> 4) + ((adlen & 15) ? 1 : 0);
    m = plain_text_len >> 4;
    
    printf("a: %d, m: %d\nplain text len: %llu, adlen: %llu\n", a, m, plain_text_len, adlen);
    /* TODO: pad plain_text, associated_data. */
    y = (uint64_t*)malloc(plain_text_len + adlen + 16);
    x = (uint64_t*)malloc(plain_text_len + adlen);
    
    printf("x: %p\n", x);

    cipher_text = (uint8_t*)malloc(plain_text_len);
    printf("init\n"); 

    gift128_encrypt(nonce, key, (uint8_t*)y);
    printf("Ek(nonce): %s\n", bytes_to_hex((uint8_t*)y, 16));
    L = ((uint64_t*)y)[0];
    printf("L: %s\n", bytes_to_hex((uint8_t*)&L, 8));

    printf("x: %p\n", x);
    process_associated_data(y, x, associated_data, adlen, a, key, &L);

    // for (i = 0; i < m - 1; i++)
    // {
    //     L = L << 1;
    //     j = i << 1; /* j = 2 * i */
    //     k = j + 1; /* k = 2 * i + 1 */
    //     *((uint64_t*)cipher_text + j) = ((uint64_t*)plain_text)[j] ^ y[j + a + 2]; 
    //     *((uint64_t*)cipher_text + k) = ((uint64_t*)plain_text)[k] ^ y[k + a + 2]; 
    //     x[j + a] = ((uint64_t*)plain_text)[j] ^ y[k + a + 2] ^ L;
    //     x[k + a] = ((uint64_t*)plain_text)[k] ^ ROTATE_LEFT_64(y[j + a + 2], 1); 
    //     gift128_encrypt((uint8_t*)&x[j + a], key, (uint8_t*)&y[j + a + 2]);
    // }

    process_plain_text(cipher_text, y, x, plain_text, plain_text_len, key, &L, a, m);

    free(y);
    free(x);
    printf("cipher text: %s\n", bytes_to_hex(cipher_text, 16));
    return cipher_text;
}

void process_associated_data(uint64_t *y, uint64_t *x, uint8_t *associated_data, uint64_t adlen, uint32_t a, uint8_t *key, uint64_t *L)
{
    printf("process_associated_data\n");
    uint32_t i;
    uint64_t last_block[2];
    for (i = 0; i < a - 1; i++)
    {
	printf("i: %d\n", i);
        double_half_block((uint8_t*)L, (uint8_t*)L); /* L <- 2.L */
	process_ad_block(y, x, (uint64_t*)associated_data , key, i << 1, L);
	printf("--- i: %d\n", i);
    }

    triple_half_block((uint8_t*)L, (uint8_t*)L);
    if (adlen & 15) 
	triple_half_block((uint8_t*)L, (uint8_t*)L);

    pad((uint8_t*)last_block, associated_data, adlen);
    process_ad_block(y, x, last_block, key, (a - 1) << 1, L);
}

void process_ad_block(uint64_t *y, uint64_t *x, uint64_t *associated_data, uint8_t *key, uint32_t j, uint64_t *L)
{
    uint32_t k;
    k = j + 1;
    x[j] = *associated_data ^ y[k] ^ *L;
    printf("x 0 done\n");
    x[k] = *(associated_data + 1) ^ rotate_left_64((uint8_t*)(y + j));
    gift128_encrypt((uint8_t*)&x[j], key, (uint8_t*)(y + j + 2));
}

void process_plain_text(uint8_t *cipher_text, uint64_t *y, uint64_t *x, uint8_t *plain_text, uint64_t plain_text_len, uint8_t *key, uint64_t *L, uint32_t a, uint32_t m)
{
    triple_half_block((uint8_t*)L, (uint8_t*)L);
    process_plain_text_block(cipher_text, y, x, (uint64_t*)plain_text, key, (m - 1) << 1, L, a);
}

void process_plain_text_block(uint8_t *cipher_text, uint64_t *y, uint64_t *x, uint64_t *plain_text_block, uint8_t *key, uint32_t j, uint64_t *L, uint32_t a)
{
    uint32_t k;
    k = j + 1;
    
    *((uint64_t*)cipher_text + j) = *plain_text_block ^ y[j + 2 * a]; 
    *((uint64_t*)cipher_text + k) = *(plain_text_block + 1) ^ y[k + 2 * a]; 
    
    x[j + a] = *plain_text_block ^ y[k + a + 2] ^ *L;
    x[k + a] =  *(plain_text_block + 1) ^ rotate_left_64((uint8_t*)(y + j + a + 2)); 
    gift128_encrypt((uint8_t*)(x + j + a), key, (uint8_t*)(y + j + a + 2));
}

void double_half_block(uint8_t* d, uint8_t* s) {
    uint8_t i;
    uint8_t tmp[8];
    /*x^{64} + x^4 + x^3 + x + 1*/
    for (i=0; i<7; i++)
        tmp[i] = (s[i] << 1) | (s[i+1] >> 7);
    tmp[7] = (s[7] << 1) ^ ((s[0] >> 7) * 27);

    for(i=0; i<8; i++)
        d[i] = tmp[i];
}

void triple_half_block(uint8_t* d, uint8_t* s) {
    uint8_t i;
    uint8_t tmp[8];
    double_half_block(tmp,s);
    for (i=0; i<8; i++)
        d[i] = s[i] ^ tmp[i];
}

void pad(uint8_t *result, uint8_t *block, uint32_t len)
{
    uint8_t dif;
    dif =  len & 15;
    printf("dif: %d\n", dif);
    block = block + len - dif;
    if (dif)
    {
	printf("pad : %s\n", bytes_to_hex(block, 1));
	memcpy(result, block, dif);
	result[dif] = 0x80;
	if (dif < 15)
	    memset(result + dif + 1, 0, 16 - dif - 1);
    }
    else
	memcpy(result, block, 16);
}
	
int main() 
{
    /*
    Count = 545
    Key = 000102030405060708090A0B0C0D0E0F
    Nonce = 000102030405060708090A0B0C0D0E0F
    PT = 000102030405060708090A0B0C0D0E0F
    AD = 000102030405060708090A0B0C0D0E0F
    CT = 3BFF715A56CBA49D1F7AC0691A966FDCBF77814044BF3FC9A9DEBBD393F545D4
    */
    char message_hex[] = "000102030405060708090A0B0C0D0E0F";
    char key_hex[] =     "000102030405060708090A0B0C0D0E0F";
    char ad_hex[] =      "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E";
    char nonce_hex[] =   "000102030405060708090A0B0C0D0E0F";

    uint8_t *cipher_text;
    uint8_t *message = hex_to_bytes(message_hex, sizeof(message_hex));
    uint32_t message_len = sizeof(message_hex) / 2;
    uint8_t *key = hex_to_bytes(key_hex, 32);
    uint8_t *nonce = hex_to_bytes(nonce_hex, 32);
    uint8_t *ad = hex_to_bytes(ad_hex, sizeof(ad_hex));
    uint32_t adlen = sizeof(ad_hex) / 2;

    cipher_text = (uint8_t*)malloc(16);
    //gift128_encrypt(nonce, key, cipher_text);
    printf("adlen: %d\n", adlen);
    cipher_text = encrypt(message, message_len, key, ad, adlen, nonce);
    printf("encryption complete\n");
    printf("%s\n", bytes_to_hex(cipher_text, 16));
    free(cipher_text);
    free(message);
    printf("done!\n");

    uint64_t k = 5, r;
    triple_half_block((uint8_t*)&r, (uint8_t*)&k);
    printf("%llu\n", r);
    return 0;
}
