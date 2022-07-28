#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "../../utils/hex_utils.h"
#include "gift128.h"

#define GIFT128_N_ROUNDS 40

#define S(n) (state->s[n])
#define W(n) (state->ks[n])

/* Rotates the 32 bit word by n to the right 
 * n must be < 16  */
#define ROTATE_RIGHT_16(w, n) (((w) >> (n)) | ((w) << (16 - (n))))

typedef struct 
{
    uint32_t s[4];
    uint16_t ks[8];
} State;

const uint8_t round_constants[] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A
};

void initialize(State *state, uint8_t *plain_text_block, uint8_t *key);
void subcells(State *state);
void permbits(State *state);
uint32_t permute_row(uint32_t row, int B0_pos, int B1_pos, int B2_pos, int B3_pos);
void add_round_key(State* state, uint32_t round_key_u, uint32_t round_key_v, uint8_t round_constant);
void key_schedule(State *state, uint32_t *round_key_u, uint32_t *round_key_v);
void prepare_cipher_text(State *state, uint8_t *cipher_text);

void gift128_encrypt(uint8_t *plain_text_block, uint8_t *key, uint8_t *cipher_text)
{
    uint8_t i;
    uint32_t round_key_u, round_key_v;
    State state;
    initialize(&state, plain_text_block, key);

    // printf("after init (r = %d): %s\n", i, bytes_to_hex((uint8_t*)state.ks, 16));

    for (i = 0; i < GIFT128_N_ROUNDS; i++)
    {
	subcells(&state);
	//printf("after subcell (r = %d) : %s\n", i, bytes_to_hex((uint8_t*)state.s, 16));
	permbits(&state);
	//printf("after permbits (r = %d): %s\n", i, bytes_to_hex((uint8_t*)state.s, 16));
	key_schedule(&state, &round_key_u, &round_key_v);
	// printf("after subcell (r = %d) : %s\n", i, bytes_to_hex((uint8_t*)state.ks, 16));
	add_round_key(&state, round_key_u, round_key_v, round_constants[i]);
    }

    // memcpy(cipher_text, state.s, 16);
    prepare_cipher_text(&state, cipher_text);
}
	

void initialize(State *state, uint8_t *plain_text_block, uint8_t *key)
{
    uint8_t i;
    // S(0) = *((uint32_t*)plain_text_block);
    // S(1) = *((uint32_t*)(plain_text_block + 4));
    // S(2) = *((uint32_t*)(plain_text_block + 8));
    // S(3) = *((uint32_t*)(plain_text_block + 12));

    // *((uint32_t*)(&W(0))) = *((uint32_t*)key); 
    // *((uint32_t*)(&W(2))) = *((uint32_t*)(key + 4)); 
    // *((uint32_t*)(&W(4))) = *((uint32_t*)(key + 8)); 
    // *((uint32_t*)(&W(6))) = *((uint32_t*)(key + 12)); 
    for (i = 0; i < 4; i++)
	S(i) = ((uint32_t)plain_text_block[i << 2] << 24) | ((uint32_t)plain_text_block[(i << 2) + 1] << 16) | ((uint32_t)plain_text_block[(i << 2) + 2] << 8) | (uint32_t)plain_text_block[(i << 2) + 3];
    
    for (i = 0; i < 8; i++)
	W(i) = ((uint16_t)key[i << 1] << 8) | ((uint16_t)key[(i << 1) + 1]);
    // memcpy(state->s, plain_text_block, 16);
    // memcpy(state->ks, key, 16);
}

void subcells(State *state)
{
    uint32_t temp;
    S(1) ^= S(0) & S(2);
    S(0) ^= S(1) & S(3);
    S(2) ^= S(0) | S(1);
    S(3) ^= S(2);
    S(1) ^= S(3);
    S(3) = ~S(3);
    S(2) ^= S(0) & S(1);

    temp = S(0);
    S(0) = S(3);
    S(3) = temp;
}

void permbits(State *state)
{
    S(0) = permute_row(S(0), 0, 3, 2, 1);
    S(1) = permute_row(S(1), 1, 0, 3, 2);
    S(2) = permute_row(S(2), 2, 1, 0, 3);
    S(3) = permute_row(S(3), 3, 2, 1, 0);
}

uint32_t permute_row(uint32_t row, int B0_pos, int B1_pos, int B2_pos, int B3_pos)
{
    uint32_t result = 0;
    int i;
    for(i = 0; i < 8; i++){
        result |= ((row>>(4*i+0))&0x1)<<(i + 8*B0_pos);
        result |= ((row>>(4*i+1))&0x1)<<(i + 8*B1_pos);
        result |= ((row>>(4*i+2))&0x1)<<(i + 8*B2_pos);
        result |= ((row>>(4*i+3))&0x1)<<(i + 8*B3_pos);
    }
    return result;
}

void add_round_key(State* state, uint32_t round_key_u, uint32_t round_key_v, uint8_t round_constant)
{
    S(2) ^= round_key_u;
    S(1) ^= round_key_v;
    S(3) ^= 0x80000000 ^ round_constant;
}

/**
 * Updates the key state and returns the round key 
 */
void key_schedule(State *state, uint32_t *round_key_u, uint32_t *round_key_v)
{
    uint16_t temp, temp2;
    *round_key_u = ((uint32_t)W(2) << 16) | (uint32_t)W(3);
    *round_key_v = ((uint32_t)W(6) << 16) | (uint32_t)W(7);

    temp = W(0);
    W(0) = ROTATE_RIGHT_16(W(6), 2);
    temp2 = W(2);
    W(2) = temp;
    temp = W(4);
    W(4) = temp2;
    W(6) = temp;

    temp = W(1);
    W(1) = ROTATE_RIGHT_16(W(7), 12);
    temp2 = W(3);
    W(3) = temp;
    temp = W(5);
    W(5) = temp2;
    W(7) = temp;
}

void prepare_cipher_text(State *state, uint8_t *cipher_text)
{
    uint8_t i, j;
    for (i = 0; i < 4; i++)
    {
	j = i << 2; /* j = 2i */
	cipher_text[j] = S(i) >> 24;
	cipher_text[j + 1] = S(i) >> 16;
	cipher_text[j + 2] = S(i) >> 8;
	cipher_text[j + 3] = S(i);
    }
}
