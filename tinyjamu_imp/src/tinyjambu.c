#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


#define FRAME_BITS_NONCE 0x10
#define FRAME_BITS_AD 0x30
#define FRAME_BITS_PLAIN_CIPHER 0x50
#define FRAME_BITS_FINALIZE 0x70

#define N_ROUNDS_1 640
#define N_ROUNDS_2 1024


char* bytes_to_hex(uint8_t* bytes, uint32_t len);

void update_state_single(uint32_t *state, uint8_t* key, uint32_t count)
{
    uint32_t feedback, s0, s47, s70, s85, s91;
    s0 = state[0];
    // s47 = (state[1] << 14) | (state[2] >> 16);
    // s70 = (state[2] << 5) | (state[3] >> 25);
    // s85 = (state[2] << 20) | (state[3] >> 10);
    // s91 = (state[2] << 26) | (state[3] >> 4);

    s47 = (state[1] >> 15) | (state[2] << 17);
    s70 = (state[2] >> 6) | (state[3] << 26);
    s85 = (state[2] >> 21) | (state[3] << 11);
    s91 = (state[2] >> 27) | (state[3] << 5);

    feedback = s0 ^ s47 ^ (~(s70 & s85)) ^ s91 ^ ((uint32_t*)key)[count & 3];
    state[0] = state[1];
    state[1] = state[2];
    state[2] = state[3];
    state[3] = feedback;
}

void update_state(uint32_t *state, uint8_t *key, uint32_t n_rounds)
{
    uint32_t i, n;
    n = n_rounds >> 5;

    for (i = 0; i < n; i++) 
	update_state_single(state, key, i);
}

void initialize(uint32_t* state, uint8_t *key, uint8_t *nonce)
{
    uint8_t i;
    state[0] = 0;
    state[1] = 0;
    state[2] = 0;
    state[3] = 0;

    update_state(state, key, N_ROUNDS_2);

    for (i = 0; i < 3; i++)
    {
	state[1] ^= FRAME_BITS_NONCE;
	update_state(state, key, N_ROUNDS_1);
	state[3] ^= ((uint32_t*)nonce)[i];
    }
}

void process_ad(uint32_t *state, uint8_t* key, uint8_t *ad, uint32_t adlen) 
{
    printf("adlen=%d\n", adlen);
    uint32_t i, lenp;
    uint32_t n, startp;
    n = adlen >> 2;

    for (i = 0; i < n; i++) 
    {
	 state[1] ^= FRAME_BITS_AD;
	 update_state(state, key, N_ROUNDS_1);
	 state[3] ^= ((uint32_t*)ad)[i];
    }

    lenp = adlen & 3; // adlen % 32 
    printf("lenp=%d\n", lenp);

    if (lenp > 0) 
    {
	 startp = adlen - lenp;
	 printf("startp=%d\n", startp);
	 state[1] ^= FRAME_BITS_AD;
	 update_state(state, key, N_ROUNDS_1);
	 for (i = 0; i < lenp; i++)
	    ((uint8_t*)state)[12 + i] ^= ad[startp + i];
	 state[1] ^= lenp;
    }
}

void process_plaintext(uint32_t *state, uint8_t *key, uint8_t *message, uint32_t message_len, uint8_t *cipher_text)
{
    uint8_t i, lenp;
    uint32_t n, startp;
    n = message_len >> 2; // message_len / 4

    for (i = 0; i < n; i++) 
    {
	 state[1] ^= FRAME_BITS_PLAIN_CIPHER;
	 update_state(state, key, N_ROUNDS_2);
	 state[3] ^= ((uint32_t*)message)[i];
	 ((uint32_t*)cipher_text)[i] = state[2] ^ ((uint32_t*)message)[i];
    }

    lenp = message_len & 3; // message_len % 4

    if (lenp > 0) 
    {
         startp = message_len - lenp;
         state[1] ^= FRAME_BITS_PLAIN_CIPHER;
         update_state(state, key, N_ROUNDS_2);
         for (i = 0; i < lenp; i++)
         {
            ((uint8_t*)state)[12 + i] ^= message[startp + i];
            cipher_text[startp + i] = ((uint8_t*)state)[8 + i] ^ message[startp + i];
         }
         state[1] ^= lenp;
    }
}

void finalize_encrypt(uint32_t *state, uint8_t *key, uint8_t *tag) 
{
    state[1] ^= FRAME_BITS_FINALIZE;
    update_state(state, key, N_ROUNDS_2);
    ((uint32_t*)tag)[0] = state[2];
    
    state[1] ^= FRAME_BITS_FINALIZE;
    update_state(state, key, N_ROUNDS_1);
    ((uint32_t*)tag)[1] = state[2];
}

uint8_t* encrypt(uint8_t *message, const uint32_t message_len, uint8_t *key, uint8_t *nonce, uint8_t *ad, uint32_t adlen, uint8_t* tag)
{
    uint32_t state[4];
    uint8_t *cipher_text;
    printf("%d\n", message_len);
    cipher_text = (uint8_t*)malloc(message_len + 1);

    initialize(state, key, nonce);
    process_ad(state, key, ad, adlen);
    process_plaintext(state, key, message, message_len, cipher_text);
    finalize_encrypt(state, key, tag);
    return cipher_text;
}

void processs_cipher_text(uint32_t *state, uint8_t *key, uint8_t *cipher_text, uint32_t cipher_text_len, uint8_t *plain_text)
{
    uint8_t i, lenp;
    uint32_t n, startp;
    n = cipher_text_len >> 2;

    for (i = 0; i < n; i++) 
    {
	 state[1] ^= FRAME_BITS_PLAIN_CIPHER;
	 update_state(state, key, N_ROUNDS_2);
	 ((uint32_t*)plain_text)[i] = state[2] ^ ((uint32_t*)cipher_text)[i];
	 state[3] ^= ((uint32_t*)plain_text)[i];
    }

    lenp = cipher_text_len & 3; // message_len % 32 

    if (lenp > 0) 
    {
         startp = cipher_text_len - lenp;
         state[1] ^= FRAME_BITS_PLAIN_CIPHER;
         update_state(state, key, N_ROUNDS_2);
         for (i = 0; i < lenp; i++)
         {
            plain_text[startp + i] = ((uint8_t*)state)[8 + i] ^ cipher_text[startp + i];
            ((uint8_t*)state)[12 + i] ^= plain_text[startp + i];
         }
         state[1] ^= lenp;
    }
}

uint8_t* decrypt(uint8_t* cipher_text, const uint32_t cipher_text_len, uint8_t* key, uint8_t *nonce, uint8_t *ad, uint32_t adlen, uint8_t* tag)
{

    uint32_t state[4];
    uint8_t valid;
    uint8_t tag_[8];
    uint8_t *plaintext;

    plaintext = (uint8_t*)malloc(cipher_text_len + 1);
    initialize(state, key, nonce);
    process_ad(state, key, ad, adlen);
    processs_cipher_text(state, key, cipher_text, cipher_text_len, plaintext);
    finalize_encrypt(state, key, tag_);
    printf("tag' : %s\n", bytes_to_hex(tag_, 8));
    valid = *((uint64_t*)tag) == *((uint64_t*)tag_);
    printf("valid : %d\n", valid);
    return plaintext;
}

uint8_t* hex_to_bytes(char *hex_string, uint32_t len)
{
    uint8_t b;
    uint32_t i;
    uint8_t* result = (uint8_t*)malloc(len / 2 + 1);
    char hex_byte[3] = "00";

    for (i = 0 ; i < len / 2; i++) 
    {
	hex_byte[0] = hex_string[2 * i];
	hex_byte[1] = hex_string[2 * i + 1];
	b = (uint8_t)strtol(hex_byte, NULL, 16);
	result[i] = b;	
    }

    result[len / 2] = '\0'; 
    return result;
}

char* bytes_to_hex(uint8_t* bytes, uint32_t len)
{
    char h;
    uint32_t i;
    char* result = (char*)malloc(len * 2 + 1);

    for (i = 0; i < len; i++)
    {
	sprintf(&result[2 * i], "%02X", bytes[i]);
    }

    result[len * 2] = '\0';
    return result;
}

int main() 
{
    uint8_t *cipher_text, *plain_text;
    uint8_t tag[8];
    /* Test vector 451 */
    char message_hex[] = "00";
    char ad_hex[] = "";

    char key_hex[] = "000102030405060708090A0B0C0D0E0F";
    char nonce_hex[] = "000102030405060708090A0B";
    
    uint8_t* message = hex_to_bytes(message_hex, sizeof(message_hex));
    uint32_t message_len = sizeof(message_hex) / 2;
    uint8_t* ad = hex_to_bytes(ad_hex, sizeof(ad_hex));
    uint32_t adlen = sizeof(ad_hex) / 2;
    uint8_t* key = hex_to_bytes(key_hex, sizeof(key_hex));
    uint8_t *nonce = hex_to_bytes(nonce_hex, sizeof(nonce_hex));

    cipher_text = encrypt(message, message_len, key, nonce, ad, adlen, tag);
    plain_text = decrypt(cipher_text, message_len, key, nonce, ad, adlen, tag);

    printf("cipher text         : %s\n", bytes_to_hex(cipher_text, message_len));
    printf("decrypted plain text: %s\n", bytes_to_hex(plain_text, message_len));
    printf("tag                 : %s\n", bytes_to_hex(tag, 8));
    printf("done!");
}
