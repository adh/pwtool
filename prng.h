#ifndef H__prng__
#define H__prng__

#include <stdlib.h>
#include <stdint.h>

void prng_init();
void prng_get_bytes(uint8_t* buf, size_t len);

#endif
