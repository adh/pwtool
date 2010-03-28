#include "prng.h"
#include "sha256.h"
#include "aes.h"
#include <time.h>
#include <fcntl.h>

aes_context aes_ctx;
uint8_t prng_state[16];
uint8_t prng_key[48];

uint8_t prng_output[32];
int prng_output_ptr = 16;

void prng_init(){
  sha256_context sc;
  uint8_t keybuf[64];
  int fd;
  uint32_t tmp;
  
  fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0){
    read(fd, keybuf, 64);
    close(fd);
  }

  sha256_starts(&sc);
  sha256_update(&sc, keybuf, 64);
  sha256_update(&sc, &fd, 4);
  tmp = &fd;
  sha256_update(&sc, &tmp, 4);
  tmp = time(NULL);
  sha256_update(&sc, &tmp, 4);
  sha256_finish(&sc, keybuf);

  aes_set_key(&aes_ctx, keybuf, 128);
  memcpy(prng_key, keybuf + 16, 48);
}
void prng_mix(uint8_t* buf, size_t len){
  sha256_context sc;
  
  sha256_starts(&sc);
  sha256_update(&sc, prng_key, 48);
  sha256_update(&sc, buf, len);
  sha256_finish(&sc, prng_key);
}
void prng_get_bytes(uint8_t* buf, size_t len){
  while (len){
    if (prng_output_ptr == 16){
      sha256_context sc;
      prng_output_ptr = 0;
      
      aes_encrypt(&aes_ctx, prng_state, prng_state);
      
      sha256_starts(&sc);
      sha256_update(&sc, prng_state, 16);
      sha256_update(&sc, prng_key, 64);
      sha256_finish(&sc, prng_output);
    }

    *buf = prng_output[prng_output_ptr];
    prng_output_ptr++;
    len--;
    buf++;
  }
}
