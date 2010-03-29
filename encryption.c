/*
 * pwtool - Simple password manager
 * Copyright (c) 2010 Ales Hakl
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "encryption.h"
#include "sha256.h"
#include "aes.h"
#include "prng.h"

#include <string.h>

#include <gc/gc.h>

aes_context aes;
uint8_t hmac_key[32];
uint8_t recordid_key[32];

void set_keys(uint8_t master_key[32]){
  sha256_context sh;
  uint8_t buf[32];

  sha256_starts(&sh);
  sha256_update(&sh, "H", 1);
  sha256_update(&sh, master_key, 32);
  sha256_finish(&sh, hmac_key);

  sha256_starts(&sh);
  sha256_update(&sh, "R", 1);
  sha256_update(&sh, master_key, 32);
  sha256_finish(&sh, recordid_key);

  sha256_starts(&sh);
  sha256_update(&sh, "E", 1);
  sha256_update(&sh, master_key, 32);
  sha256_finish(&sh, buf);
    
  aes_set_key(&aes, buf, 256);
}

static void calculate_hmac(uint8_t key[32],
                           char* buf, size_t len, uint8_t res[32]){
  int i;
  uint8_t hmacbuf[32];
  uint8_t hmac_keybuf[64];
  sha256_context sc;

  for (i = 0; i < 32; i++){
    hmac_keybuf[i] = key[i] ^ 0x36;
  }
  memset(hmac_keybuf + 32, 0x36, 32);
  sha256_starts(&sc);
  sha256_update(&sc, hmac_keybuf, 32);
  sha256_update(&sc, buf, len);
  sha256_finish(&sc, hmacbuf);

  for (i = 0; i < 32; i++){
    hmac_keybuf[i] = key[i] ^ 0x5c;
  }
  memset(hmac_keybuf + 32, 0x5c, 32);
  sha256_starts(&sc);
  sha256_update(&sc, hmac_keybuf, 32);
  sha256_update(&sc, hmacbuf, 32);
  sha256_finish(&sc, res);
}

void derive_key(char* passphrase, 
                uint8_t salt[32], 
                uint8_t key[32]){
  int i;
  int j;
  uint8_t buf[32];
  sha256_context sc;

  memcpy(key, salt, 32);

  for (i = 0; i < 4096; i++){
    calculate_hmac(key, passphrase, strlen(passphrase), buf);
    for (j = 0; j < 32; j++){
      key[j] ^= buf[j];
    }
  }
}

void encrypt_record(char* ibuf, size_t ilen, char**obuf, size_t *olen){
  int i;
  uint8_t keybuf[16];

  *obuf = GC_MALLOC_ATOMIC(ilen+48);
  *olen = ilen + 48;
  
  prng_get_bytes(keybuf, 16);

  memcpy(*obuf, keybuf, 16);

  for (i = 0; i < ilen; i++){
    if ((i % 16) == 0){
      aes_encrypt(&aes, keybuf, keybuf);
    }

    (*obuf)[i + 16] = ibuf[i] ^ keybuf[i % 16];
  }

  calculate_hmac(hmac_key, *obuf, ilen + 16, *obuf + ilen + 16);
}
int decrypt_record(char* ibuf, size_t ilen, char**obuf, size_t *olen){
  int i;
  uint8_t keybuf[16];
  uint8_t hmacbuf[32];

  if (ilen < 48){
    return 0;
  }

  calculate_hmac(hmac_key, ibuf, ilen - 32, hmacbuf);
  if (memcmp(hmacbuf, ibuf + ilen - 32, 32) != 0){
    return 0;
  }
  
  *olen = ilen - 48;
  *obuf = GC_MALLOC_ATOMIC((*olen) + 1);

  memcpy(keybuf, ibuf, 16);

  for (i = 0; i < ilen - 48; i++){
    if ((i % 16) == 0){
      aes_encrypt(&aes, keybuf, keybuf);
    }

    (*obuf)[i] = ibuf[i + 16] ^ keybuf[i % 16];
  }
  
  (*obuf)[*olen] = 0;

  return 1;
}

void hash_record_id(char* type, char* id, uint8_t hash[32]){
  size_t type_len = strlen(type);
  size_t id_len = strlen(id);
  char* buf = GC_MALLOC_ATOMIC(type_len + id_len + 1);
  memcpy(buf, type, type_len);
  memcpy(buf + type_len + 1, id, id_len);
  buf[type_len] = 0;

  calculate_hmac(recordid_key, buf, type_len + id_len + 1, hash);
}

