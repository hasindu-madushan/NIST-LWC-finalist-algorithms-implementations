// 17 Nov 2022
#include <stdint.h>


#define MAXROUNDS 12
#define NROWS 3
#define NCOLUMS 4
#define NLANES (NCOLUMS*NROWS)

#define LANESIZE 4
#define LANES_PER_PLANE 4
#define PLANE_SIZE (LANES_PER_PLANE * LANESIZE)
#define NPLANES 3
#define STATE_SIZE (PLANE_SIZE * NPLANES)


void xoodoo(uint8_t *state);
