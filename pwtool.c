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

#include "prng.h"
#include "encryption.h"

#include <readline/readline.h>
#include <gc/gc.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <errno.h>
#include <tcutil.h>
#include <tchdb.h>
#include <getopt.h>

#include "sha256.h"

TCHDB* database;
char* database_filename;

char* read_passphrase(char* prompt){
  char *buf;
  size_t ptr;
  int fd;
  struct termios old, new;
  char ch;

  buf = malloc(4096);

  fd = open("/dev/tty", O_RDWR);
  if (fd <0){
    perror("open: /dev/tty");
  }

  write(fd, prompt, strlen(prompt));

  tcgetattr (fd, &old);
  new = old;
  new.c_lflag &= ~ECHO;
  tcsetattr (fd, TCSAFLUSH, &new);
    
  ptr = 0;

  while (read(fd, &ch, 1) == 1){
    switch (ch){
    case '\0':
    case '\n':
      goto out;
    default:
      buf[ptr] = ch;
      ptr++;
      break;
    }
  }

 out:
  buf[ptr] = '\0';

  tcsetattr (fd, TCSAFLUSH, &old);
  write(fd, "\n", 1);

  return buf;
}

int file_exists(char* filename){
  struct stat st;

  if (stat(filename, &st) < 0){
    if (errno == ENOENT){
      return 0;
    } else {
      perror(filename);
      exit(1);
    }
  }
  
  if (!S_ISREG(st.st_mode)){
    fprintf(stderr, "%s exists but is not regular file", filename);
    exit(1);
  }

  return 1;
}

char* get_default_database_file(){
  char* name = getenv("PWTOOL_DATABASE_FILE");
  char* home = getenv("HOME");

  if (!name){
    name = GC_MALLOC_ATOMIC(strlen(home) + strlen("/.pwtool.db") + 1);
    strcpy(name, home);
    strcat(name, "/.pwtool.db");
  }

  return name;
}

void init_database(){
  char* passphrase = read_passphrase("Enter passphrase: ");
  char* confirm = read_passphrase("Again: ");
  char* password;
  int ret;
  uint8_t master_key[32];
  uint8_t salt[32];
  int creating;
  uint8_t vrfy_key[32];


  if (strcmp(passphrase, confirm) != 0){
    fprintf(stderr, "Passphrases does not match\n");
    exit(1);
  }
  free(confirm);

  prng_mix(passphrase, strlen(passphrase));
  database = tchdbnew();
  
  if (!tchdbopen(database, database_filename, 
                 HDBOWRITER | HDBOCREAT | HDBOTSYNC)){
    fprintf(stderr, "Cannot open %s\n", database_filename);
    exit(1);
  }
  
  prng_get_bytes(salt, 32);
  derive_key(passphrase, salt, master_key);
  set_keys(master_key);
  hash_record_id("crypto", "key-verify", vrfy_key);

  tchdbtranbegin(database);
  tchdbput2(database, "format", "pwtool version=1");
  tchdbput(database, "crypto-salt", 11, salt, 32);
  tchdbput(database, "key-verify", 10, vrfy_key, 8);
  tchdbtrancommit(database);
  
}

void open_database(){
  char* passphrase;
  char* password;
  int ret;
  uint8_t master_key[32];
  uint8_t *salt;
  int creating;
  uint8_t vrfy_key[32];

  database = tchdbnew();

  char* tmp;
  int len;
  if (!tchdbopen(database, database_filename, 
                 HDBOWRITER | HDBOTSYNC)){
    fprintf(stderr, "Cannot open %s\n", database_filename);
    exit(1);
  }

  tmp = tchdbget2(database, "format");
  if (!tmp || strcmp("pwtool version=1", tmp) != 0){
    fprintf(stderr, "Invalid database format\n");
    exit(1);
  }
  free(tmp);

  salt = tchdbget(database, "crypto-salt", 11, &len);
  if (!salt || len != 32){
    fprintf(stderr, "Inconsistent database\n");
    exit(1);
  }

  passphrase = read_passphrase("Enter passphrase: ");
  prng_mix(passphrase, strlen(passphrase));
  derive_key(passphrase, salt, master_key);
  free(salt);
  set_keys(master_key);
  hash_record_id("crypto", "key-verify", vrfy_key);

  int vrfy_len;
  char* vrfy_read = tchdbget(database, "key-verify", 10, &vrfy_len);
  if (vrfy_len != 8 || memcmp(vrfy_read, vrfy_key, 8) != 0){
    hexdump(vrfy_key, 8);
    hexdump(vrfy_read, 8);
    fprintf(stderr, "Invalid passphrase\n");
    exit(1);
  }
}

void hexdump(uint8_t* buf, size_t len){
  while (len) {
    printf("%02hhx ", *buf);
    len--;
    buf++;
  }
  printf("\n");
}

typedef struct idx_entry_t idx_entry_t;

struct idx_entry_t {
  char* name;
  idx_entry_t* next;
};

char* stracpy(char* ptr){
  size_t len = strlen(ptr);
  char* res = GC_MALLOC_ATOMIC(len + 1);
  memcpy(res, ptr, len + 1);
  return res;
}

typedef struct strlist_t strlist_t;
typedef struct strlist_entry_t strlist_entry_t;

struct strlist_entry_t {
  strlist_entry_t *next;  
  char* data;
  size_t len;
};

struct strlist_t {
  strlist_entry_t *head;
  strlist_entry_t *tail;
  size_t len;
};


strlist_t* strlist_create(){
  strlist_t* sl;

  sl = GC_NEW(strlist_t);
  if (!sl)
    return NULL;

  sl->len = 0;
  sl->head = NULL;
  sl->tail = NULL;
  
  return sl;
}
int strlist_append(strlist_t* l, char* str){
  strlist_entry_t* e;
  size_t len;

  e = GC_NEW(strlist_entry_t);

  if (!e)
    return 0;

  len = strlen(str);

  e->next = NULL;
  e->data = str;
  e->len = len;
  l->len += len;

  if (l->head){
    l->tail->next = e;
    l->tail = e;
  }else{
    l->tail = e;
    l->head = e;
  }

  return 1;
}
char* strlist_value(strlist_t* l){
  char* buf;
  size_t c;
  strlist_entry_t* i;

  buf = GC_MALLOC_ATOMIC(l->len + 1);
  if (!buf)
    return NULL;

  i = l->head;
  c = 0;

  while (i){
    memcpy(buf+c, i->data, i->len);
    c += i->len;
    i = i->next;
  }

  buf[c] = '\0';
  return buf;
}

char* strlist_value_nl(strlist_t* l){
  char* buf;
  size_t c;
  strlist_entry_t* i;

  buf = GC_MALLOC_ATOMIC(l->len + 1);
  if (!buf)
    return NULL;

  i = l->head;
  c = 0;

  while (i){
    memcpy(buf+c, i->data, i->len);
    buf[c + i->len] = '\n';
    c += i->len + 1;
    i = i->next;
  }

  buf[c] = '\0';
  return buf;
}

idx_entry_t* read_index(){
  idx_entry_t* idx_head = NULL;
  idx_entry_t* idx_tail = NULL;
  idx_entry_t* tmp;
  char idx_key[32];
  char* raw_buf;
  int raw_len;
  char* idx_buf;
  char* elem_ptr;
  size_t idx_len;
  int i;

  hash_record_id("metadata", "index", idx_key);
  raw_buf = tchdbget(database, idx_key, 32, &raw_len);
  if (!raw_buf){
    return NULL;
  }

  if (!decrypt_record(raw_buf, raw_len, &idx_buf, &idx_len)){
    fprintf(strlen, "Index decryption failed!\n");
    exit(1);
  }

  free(raw_buf);

  elem_ptr = idx_buf;
  i = 0;
  while (i < idx_len){
    if (idx_buf[i] == 0){
      if (elem_ptr[0] != 0){
        tmp = GC_NEW(idx_entry_t);
        tmp->next = NULL;
        tmp->name = stracpy(elem_ptr);
        if (idx_head){
          idx_tail->next = tmp;
          idx_tail = tmp;
        } else {
          idx_head = idx_tail = tmp;
        }
      }
      i++;
      elem_ptr = idx_buf + i;
    }
    i++;
  }

  return idx_head;
}

void write_index(idx_entry_t* idx){
  size_t len = 0;
  idx_entry_t* i;
  char* buf;
  char* wptr;
  char idx_key[32];
  char* raw_buf;
  size_t raw_len;

  i = idx;
  while (i){
    len += strlen(i->name) + 1;
    i = i->next;
  }

  wptr = buf = GC_MALLOC_ATOMIC(len);
  
  i = idx;
  while (i){
    size_t elen = strlen(i->name) + 1;
    memcpy(wptr, i->name, elen);
    wptr += elen;
    i = i->next;
  }

  encrypt_record(buf, len, &raw_buf, &raw_len);
  
  hash_record_id("metadata", "index", idx_key);
  if (!tchdbput(database, idx_key, 32, raw_buf, raw_len)){
    fprintf(stderr, "Error writing index to database\n");
    exit(1);
  }
}

void add_to_index(char* elm){
  idx_entry_t* idx = read_index();
  idx_entry_t *tmp = GC_NEW(idx_entry_t);
  tmp->name = stracpy(elm);

  if (!idx || strcoll(elm, idx->name) < 0){
    tmp->next = idx;
    idx = tmp;
  } else if (strcoll(elm, idx->name) > 0){
    idx_entry_t* i = idx->next;
    idx_entry_t* j = idx;
    
    while (i){
      int res = strcoll(elm, i->name);

      if (res < 0){
        j->next = tmp;
        tmp->next = i;
        goto out;
      } else if (res == 0){
        goto out;
      }

      j = i;
      i = i->next;
    }

    j->next = tmp;
    tmp->next = NULL;
  }


 out:
  write_index(idx);
}

void remove_from_index(char* elm){
  idx_entry_t* idx = read_index();
  if (idx){
    if (strcmp(idx->name, elm) == 0){
      idx = idx->next;
    } else {
      idx_entry_t* i = idx->next;
      idx_entry_t* j = idx;

      while (i){
        if (strcmp(i->name, elm)){
          j->next = i->next;
        }
        i = i->next;
      }
    }
  }

  write_index(idx);
}

void print_index(idx_entry_t* idx){
  while (idx){
    printf("%s\n", idx->name);
    idx = idx->next;
  }
}

char* read_entry(char* name){
  uint8_t entry_key[32];
  char* raw_buf;
  int raw_len;
  size_t tmp;
  char* ret;

  add_to_index(name);
  hash_record_id("entry", name, entry_key);

  raw_buf = tchdbget(database, entry_key, 32, &raw_len);
  if (!raw_buf){
    return NULL;
  }
  
  if (!decrypt_record(raw_buf, raw_len, &ret, &tmp)){
    fprintf(stderr, "Error decrypting entry\n");
    exit(1);
  }
  
  return ret;
}

void write_entry(char* name, char* contents){
  uint8_t entry_key[32];
  char* raw_buf;
  size_t raw_len;
  tchdbtranbegin(database);
  add_to_index(name);
  hash_record_id("entry", name, entry_key);
  encrypt_record(contents, strlen(contents), &raw_buf, &raw_len);
  if (!tchdbput(database, entry_key, 32, raw_buf, raw_len)){
    fprintf(stderr, "Error writing to database");
    exit(1);
  }
  tchdbtrancommit(database);
}

void delete_entry(char* name){
  tchdbtranbegin(database);
  remove_from_index(name);

  tchdbtrancommit(database);  
}

char* password_chars = "abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ0123456789,.";

int insert_password(int count, int key){
  char* buf;
  int i;
  if (count < 2){
    count = 8;
  }

  buf = GC_MALLOC_ATOMIC(count + 1);
  prng_get_bytes(buf, count);
  buf[count] = 0;
  
  for (i = 0; i < count; i++){
    buf[i] = password_chars[buf[i] % strlen(password_chars)];
  }
  
  rl_insert_text(buf);
  rl_redisplay();
}

char* read_block(){
  strlist_t* sl = strlist_create();
  char* ret;

  fprintf(stderr, "Enter contents: (Ctrl-D or '.' to end)\n");

  while (ret = readline("> ")){
    if (strcmp(ret, ".") == 0){
      break;
    }
    
    strlist_append(sl, ret);
  }

  return strlist_value_nl(sl);
}

static void usage(){
  fprintf(stderr, "usage: pwtool [-d <database-file>] init\n");
  fprintf(stderr, "                                   list\n");
  fprintf(stderr, "                                   get <name>\n");
  fprintf(stderr, "                                   delete <name>\n");
  fprintf(stderr, "                                   put <name>\n");
  exit(1);
}

int main(int argc, char**argv){
  int opt;
  prng_init();
  database_filename = get_default_database_file();

  while ((opt = getopt(argc, argv, "hd:")) != -1){
    switch (opt){
    case 'd':
      database_filename = stracpy(optarg);
      break;
    case 'h':
    case '?':
      usage();
    }
  }


  rl_add_defun("insert-password", insert_password, '\t');
  
  argv += optind;
  argc -= optind;

  if (argc < 1){
    fprintf(stderr, "Command expected\n");
    usage();
  }

  if (strcmp(argv[0], "list") == 0){
    if (argc > 1){
      fprintf(stderr, "Too many arguments\n");
      usage();
    }
    open_database();
    print_index(read_index());
  } else if (strcmp(argv[0], "init") == 0){
    if (argc > 1){
      fprintf(stderr, "Too many arguments\n");
      usage();
    }
    init_database();
  } else if (strcmp(argv[0], "put") == 0){
    if (argc != 2){
      fprintf(stderr, "Item name expected\n");
      usage();
    }
    open_database();
    write_entry(argv[1], read_block());
  } else if (strcmp(argv[0], "delete") == 0){
    if (argc != 2){
      fprintf(stderr, "Item name expected\n");
      usage();
    }
    open_database();
    remove_from_index(argv[1]);
  } else if (strcmp(argv[0], "get") == 0){
    if (argc != 2){
      fprintf(stderr, "Item name expected\n");
      usage();
    }
    open_database();
    printf("%s\n", read_entry(argv[2]));
  } else {
    fprintf(stderr, "Unknown command\n");
    usage();
  }
}
