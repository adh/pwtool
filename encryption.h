#ifndef H__encryption__
#define H__encryption__

#include <stdlib.h>
#include <stdint.h>

void set_keys(uint8_t master_key[32]);
void derive_key(char* passphrase, uint8_t salt[32], uint8_t key[32]);

void encrypt_record(char* ibuf, size_t ilen, char**obuf, size_t *olen);
int decrypt_record(char* ibuf, size_t ilen, char**obuf, size_t *olen);

void hash_record_id(char* type, char* id, uint8_t hash[32]);

#endif
