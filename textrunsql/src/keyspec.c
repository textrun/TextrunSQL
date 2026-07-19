#include "textrunsql_pq.h"

#include "sqlite3.h"

#include <openssl/crypto.h>

#include <string.h>

int textrunsql_pq_key_sqlcipher(struct sqlite3 *db, const char *schema, const uint8_t *dek, size_t dek_len, int *sqlite_result) {
  static const char hex[] = "0123456789abcdef";
  unsigned char keyspec[68];
  size_t index;
  int result;

  if(db == NULL || schema == NULL || schema[0] == 0 || strlen(schema) > 255 || dek == NULL || dek_len != TEXTRUNSQL_PQ_DEK_BYTES || sqlite_result == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  keyspec[0] = 'x';
  keyspec[1] = '\'';
  for(index = 0; index < TEXTRUNSQL_PQ_DEK_BYTES; index++) {
    keyspec[2 + (index * 2)] = (unsigned char)hex[dek[index] >> 4];
    keyspec[3 + (index * 2)] = (unsigned char)hex[dek[index] & 0x0f];
  }
  keyspec[66] = '\'';
  keyspec[67] = 0;
  result = sqlite3_key_v2(db, schema, keyspec, 67);
  OPENSSL_cleanse(keyspec, sizeof(keyspec));
  *sqlite_result = result;
  return result == SQLITE_OK ? TEXTRUNSQL_PQ_OK : TEXTRUNSQL_PQ_ERROR_SQLCIPHER;
}
