// 17 Nov 2022

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "xoodoo.h"
#include "../../utils/hex_utils.h"


#define ROTATE_L_32(a, n) (((a) << ((n) % 32)) | ((a) >> ((32 - (n)) % 32)))
#define GET_PLANE(state, i) (state + (PLANE_SIZE) * i)

uint32_t round_constants[] = 
{
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
void shift_planes_west(uint8_t *state);
void add_round_constants(uint8_t *state, int8_t round);
void non_linear_layer(uint8_t *state);
void shift_planes_east(uint8_t *state);

void add_planes(uint8_t *output, uint8_t *plane1, uint8_t *plane2);
void shift_planes(uint8_t *state, uint8_t t1, uint8_t v1, uint8_t t2, uint8_t v2);
void shift_plane(uint8_t *output, uint8_t *plane, uint8_t t, uint8_t v);

void add_to_all_planes(uint8_t *state, uint8_t values[][PLANE_SIZE]);

void inverse_product(uint8_t *output, uint8_t *plane1, uint8_t *plane2);
void invert_plane(uint8_t *output, uint8_t *plane);
void and_planes(uint8_t *output, uint8_t *plane1, uint8_t *plane2);
uint8_t find_shifted_lane_index(uint8_t index, uint8_t offset);
uint32_t find_shifted_lane(uint8_t *plane, uint8_t index, uint8_t offset);


void xoodoo(uint8_t *state)
{
    for (int round = 1 - MAXROUNDS; round <= 0; round++)
    {
    	mix_layer(state);
	//printf("#%d state (mix col):      %s\n", round, bytes_to_hex(state, NLANES * 4));
    	shift_planes_west(state);
	//printf("#%d state (shift planes): %s\n", round, bytes_to_hex(state, NLANES * 4));
    	add_round_constants(state, round);
	//printf("#%d state (round const):  %s\n", round, bytes_to_hex(state, NLANES * 4));
    	non_linear_layer(state);
	//printf("#%d state (non lin):      %s\n", round, bytes_to_hex(state, NLANES * 4));
    	shift_planes_east(state);
	//printf("#%d state (shift east):   %s\n\n", round, bytes_to_hex(state, NLANES * 4));
	//printf("#%d state: %s\n", round, bytes_to_hex(state, NLANES * 4));
    }
}

void xoodoo_initialize(uint8_t *state)
{
    memset(state, 0, NLANES * LANESIZE);
}

void mix_layer(uint8_t *state)
{
    uint8_t p[PLANE_SIZE];
    uint8_t e[PLANE_SIZE];
    uint8_t temp[PLANE_SIZE];

    /* P = A0 + A1 + A2 */
    add_planes(p, GET_PLANE(state, 0), GET_PLANE(state, 1));
    add_planes(p, p, GET_PLANE(state, 2));

    /* E = P <<< (1, 5) + P <<< (1, 14) */
    shift_plane(e, p, 1, 5); 
    shift_plane(temp, p, 1, 14);
    add_planes(e, e, temp);
    
    /* Ay = Ay + E for y c { 0, 1, 2} */
    for (int i = 0; i < NPLANES; i++)
	add_planes(GET_PLANE(state, i), GET_PLANE(state, i), e);
}

void shift_planes_west(uint8_t *state)
{
    shift_planes(state, 1, 0, 0, 11);
}

void add_round_constants(uint8_t *state, int8_t round)
{
    ((uint32_t*)state)[0] ^= round_constants[MAXROUNDS + round - 1];
}

void non_linear_layer(uint8_t *state)
{
    uint8_t b[NPLANES][PLANE_SIZE];
    inverse_product(b[0], GET_PLANE(state, 1), GET_PLANE(state, 2)); 
    inverse_product(b[1], GET_PLANE(state, 2), GET_PLANE(state, 0)); 
    inverse_product(b[2], GET_PLANE(state, 0), GET_PLANE(state, 1)); 
    add_to_all_planes(state, b); 
}

/* Bx = Ax1'.Ax2 
 * Ax = Ax + Bx */
void inverse_product(uint8_t *output, uint8_t *plane1, uint8_t *plane2)
{
    invert_plane(output, plane1);
    and_planes(output, output, plane2);
}

void invert_plane(uint8_t *output, uint8_t *plane)
{
    for (uint8_t i = 0; i < LANES_PER_PLANE; i++)
	((uint32_t*)output)[i] = ~((uint32_t*)plane)[i];
}

void and_planes(uint8_t *output, uint8_t *plane1, uint8_t *plane2)
{
    for (uint8_t i = 0; i < LANES_PER_PLANE; i++)
	((uint32_t*)output)[i] = ((uint32_t*)plane1)[i] & ((uint32_t*)plane2)[i];
}

void add_to_all_planes(uint8_t *state, uint8_t values[][PLANE_SIZE])
{
    for (int i = 0; i < NPLANES; i++)
	add_planes(GET_PLANE(state, i), GET_PLANE(state, i), values[i]);	
}

void add_planes(uint8_t *output, uint8_t *plane1, uint8_t *plane2)
{
    for (uint8_t i = 0; i < LANES_PER_PLANE; i++)
	((uint32_t*)output)[i] = ((uint32_t*)plane1)[i] ^ ((uint32_t*)plane2)[i];
}

void shift_planes_east(uint8_t *state)
{
    shift_planes(state, 0, 1, 2, 8);
}

void shift_planes(uint8_t *state, uint8_t t1, uint8_t v1, uint8_t t2, uint8_t v2)
{
    uint8_t temp[PLANE_SIZE];
    /* A1 = A1 <<< (t1, v1) */
    shift_plane(temp, GET_PLANE(state, 1), t1, v1);
    memcpy(GET_PLANE(state, 1), temp, PLANE_SIZE);
    
    /* A2 = A2 <<< (t2, v2) */
    shift_plane(temp, GET_PLANE(state, 2), t2, v2);
    memcpy(GET_PLANE(state, 2), temp, PLANE_SIZE);
}

void shift_plane(uint8_t *output, uint8_t *plane, uint8_t t, uint8_t v) 
{
    for (uint8_t i = 0; i < LANES_PER_PLANE; i++)
	((uint32_t*)output)[i] = ROTATE_L_32(find_shifted_lane(plane, i, t), v);
}

uint32_t find_shifted_lane(uint8_t *plane, uint8_t index, uint8_t offset)
{
    int temp = (index - offset) % LANES_PER_PLANE;
    temp = temp < 0 ? LANES_PER_PLANE + temp : temp;
    return *((uint32_t*)plane + temp);
}

#ifdef XOODOO_TEST
int main()
{
    uint8_t state[NLANES * 4];
    xoodoo_initialize(state);
    xoodoo(state);
    printf("final state: %s\n", bytes_to_hex(state, NLANES * 4));

    printf("done!\n");
    return 0;
}
#endif
