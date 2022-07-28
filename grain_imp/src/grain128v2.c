#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct 
{
    uint8_t lfsr[16];
    uint8_t nfsr[16];
    uint8_t accumulator[8];
    uint8_t shift_register[8];
} State;

void initialize(State *state, uint8_t *key, uint8_t* nonce);
void lfsr_update(State *state, uint8_t y);

void initialize(State *state, uint8_t *key, uint8_t* nonce)
{
    memcpy(state->nfsr, key, 16);
    memcpy(state->lfsr, nonce, 12);
    *(uint32_t*)(&state->lfsr[12]) = 0x7FFFFFFF;
}

void lfsr_update(State *state, uint8_t y)
{
    uint8_t feedback;
    feedback = state->lfsr[3] ^ (state->lfsr[5] >> 1) ^ (state->lfsr[7] >> 6) ^ (state->lfsr[11] >> 6) ^ (state->lfsr[15] >> 7) ^ state->lfsr[15];
    feedback = (feedback ^ y) & 1;
    
}

int main()
{
    uint32_t x = 0x10000002;
    uint32_t *p = &x;
    uint8_t a3 = ((uint8_t*)p)[3];
    uint8_t a0 = ((uint8_t*)p)[0];
    uint8_t a1 = ((uint8_t*)p)[1];
    uint8_t a2 = ((uint8_t*)p)[2];
    printf("%d %d %d %d \n", a0, a1, a2, a3);
    return 0;
}
