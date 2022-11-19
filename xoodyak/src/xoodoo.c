// 17 Nov 2022

#include <stdint.h>
#include <string.h>
#include "xoodoo.h"


#define ROTATE_L_32(a, n) (((a) << ((n) % 32)) | ((a) >> ((32 - (n)) % 32)))
#define GET_PLANE(state, i) (state + (LANES_PER_PLANE * LANESIZE) * i)

uint32_t round_constants[] = {
    0x00000058,
    0x00000038,
    0x000003C0,
    0x000000D0,
    0x00000120,
    0x00000014,
    0x00000060,
    0x0000002C,
    0x00000380,
    0x000000F0,
    0x000001A0,
    0x00000012
};

void xoodoo_initialize(uint8_t *state);
void mix_layer(uint8_t *state);
void add_planes(uint8_t *output, uint8_t *plane1, uint8_t *plane2);
void rotate_plane(uint8_t *output, uint8_t *plane, uint8_t x, uint8_t y);
void shift_planes(uint8_t *state, uint8_t x1, uint8_t y1, uint8_t x2, uint8_t y2);


void xoodoo(uint8_t *state)
{
    xoodoo_initialize(state);
    mix_layer(state);
}

void xoodoo_initialize(uint8_t *state)
{
    memset(state, 0, NLANES * LANESIZE / 8);
}

void mix_layer(uint8_t *state)
{
    uint8_t p[LANES_PER_PLANE * 4];
    uint8_t e[LANES_PER_PLANE * 4];
    uint8_t temp[LANES_PER_PLANE * 4];

    /* P = A0 + A1 + A2 */
    add_planes(p, GET_PLANE(state, 0), GET_PLANE(state, 1));
    add_planes(p, p, GET_PLANE(state, 2));

    /* E = P <<< (1, 5) + P <<< (1, 14) */
    rotate_plane(e, p, 1, 5); 
    rotate_plane(temp, p, 1, 14);
    add_planes(e, e, temp);
    
    /* Ay = Ay + E for y c { 0, 1, 2} */
    for (int i = 0; i < NPLANES; i++)
	add_planes(GET_PLANE(state, i), GET_PLANE(state, i), e);
}

void add_planes(uint8_t *output, uint8_t *plane1, uint8_t *plane2)
{
    for (uint8_t i = 0; i < LANES_PER_PLANE; i++)
	((uint32_t*)output)[i] = ((uint32_t*)plane1)[i] ^ ((uint32_t*)plane2)[i];
}

void rotate_plane(uint8_t *output, uint8_t *plane, uint8_t x, uint8_t y) 
{
    for (uint8_t i = 0; i < LANES_PER_PLANE; i++)
	((uint32_t*)output)[i] = ROTATE_L_32(plane[(i - x) % 4], x);
}

void shift_planes_west(uint8_t *state)
{
    shift_planes(state, 1, 0, 0, 11);
}

void shift_planes(uint8_t *state, uint8_t x1, uint8_t y1, uint8_t x2, uint8_t y2)
{
    uint8_t temp[PLANE_SIZE];
    /* A1 = A1 <<< (x1, y1) */
    rotate_plane(temp, GET_PLANE(state, 1), x1, y1);
    memcpy(GET_PLANE(state, 1), temp, PLANE_SIZE);
    
    /* A2 = A2 <<< (x2, y2) */
    rotate_plane(temp, GET_PLANE(state, 2), x2, y2);
    memcpy(GET_PLANE(state, 2), temp, PLANE_SIZE);
}

void add_round_constants(uint8_t *state, int8_t round)
{
    ((uint32_t*)state)[0] ^= round_constants[MAXROUNDS + round - 1];
}

void non_linear_layer(uint8_t *state)
{
}

void shift_planes_east(uint8_t *state)
{
}
