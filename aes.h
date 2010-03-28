#ifndef _AES_H
#define _AES_H

#include <stdint.h>

#ifndef uint8
#define uint8  uint8_t
#endif

#ifndef uint32
#define uint32 uint32_t
#endif

typedef struct
{
    uint32 erk[64];     /* encryption round keys */
    uint32 drk[64];     /* decryption round keys */
    int nr;             /* number of rounds */
}
aes_context;

extern int  aes_set_key( aes_context *ctx, uint8 *key, int nbits );
extern void aes_encrypt( aes_context *ctx, uint8 input[16], uint8 output[16] );
extern void aes_decrypt( aes_context *ctx, uint8 input[16], uint8 output[16] );

#endif /* aes.h */
