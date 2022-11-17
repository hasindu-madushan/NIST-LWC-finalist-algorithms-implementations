// 17 Nov 2022

#include <stdint.h>
#include <string.h>
#include "xoodoo.h"


#define ROTATE32(a, n) (((a) << ((n) % 32)) | ((a) >> ((32 - (n)) % 32))
#define GET_PLANE(state, i) (state + (LANES_PER_PLANE * LANESIZE) * i)


void xoodoo_initialize(uint8_t *state)
{
    memset(state, 0, NLANES * LANESIZE / 8);
}

void mix_layer(uint8_t *state)
{

}

void add_planes(uint8_t *output, uint8_t *plane1, uint8_t *plane2)
{
    for (uint8_t i = 0; i < LANES_PER_PLANE; i++)
	((uint32_t*)output)[i] = ((uint32_t*)plane1)[i] ^ ((uint32_t*)plane2)[i];
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
