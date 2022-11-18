// 17 Nov 2022

#include <stdint.h>
#include <string.h>
#include "xoodoo.h"


#define ROTATE_L_32(a, n) (((a) << ((n) % 32)) | ((a) >> ((32 - (n)) % 32)))
#define GET_PLANE(state, i) (state + (LANES_PER_PLANE * LANESIZE) * i)

void add_planes(uint8_t *output, uint8_t *plane1, uint8_t *plane2);
void rotate_plane(uint8_t *output, uint8_t *plane, uint8_t x, uint8_t y);


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

void shift_plane_west(uint8_t *state)
{
    
}

void add_round_constants(uint8_t *state)
{
}

void non_linear_layer(uint8_t *state)
{
}

void shift_plane_east(uint8_t *state)
{
}
