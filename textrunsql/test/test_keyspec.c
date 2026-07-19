#include "textrunsql_pq.h"

#include "sqlite3.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(expression) do { if(!(expression)) { fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expression); goto cleanup; } } while(0)

typedef struct query_result {
  char value[64];
  int rows;
} query_result;

static int capture_first(void *opaque, int columns, char **values, char **names) {
  query_result *result = opaque;
  (void)names;
  if(columns > 0 && values[0] != NULL && result->rows == 0) {
    snprintf(result->value, sizeof(result->value), "%s", values[0]);
  }
  result->rows++;
  return 0;
}

static int query(sqlite3 *database, const char *sql, query_result *result) {
  char *message = NULL;
  int sqlite_result;

  memset(result, 0, sizeof(*result));
  sqlite_result = sqlite3_exec(database, sql, capture_first, result, &message);
  sqlite3_free(message);
  return sqlite_result;
}

static void make_raw_keyspec(const unsigned char dek[TEXTRUNSQL_PQ_DEK_BYTES], char keyspec[68]) {
  static const char hex[] = "0123456789abcdef";
  size_t index;

  keyspec[0] = 'x';
  keyspec[1] = '\'';
  for(index = 0; index < TEXTRUNSQL_PQ_DEK_BYTES; index++) {
    keyspec[2 + (index * 2)] = hex[dek[index] >> 4];
    keyspec[3 + (index * 2)] = hex[dek[index] & 0x0f];
  }
  keyspec[66] = '\'';
  keyspec[67] = 0;
}

int main(void) {
  static const unsigned char context[] = "textrunsql/test/database";
  sqlite3 *database = NULL;
  textrunsql_pq_key *recipient = NULL;
  textrunsql_pq_key *public_recipient = NULL;
  query_result query_value;
  unsigned char dek[TEXTRUNSQL_PQ_DEK_BYTES];
  unsigned char opened_dek[TEXTRUNSQL_PQ_DEK_BYTES];
  unsigned char wrong_dek[TEXTRUNSQL_PQ_DEK_BYTES];
  unsigned char byte_seen[256];
  unsigned char public_key[TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES];
  unsigned char envelope[TEXTRUNSQL_PQ_ENVELOPE_BYTES];
  char keyspec[68];
  char database_path[128];
  char matrix_path[128];
  char missing_path[128];
  size_t group;
  size_t index;
  size_t public_key_len = sizeof(public_key);
  size_t envelope_len = sizeof(envelope);
  int sqlite_result = SQLITE_ERROR;
  int result = 1;

  snprintf(database_path, sizeof(database_path), "build/keyspec-%ld.db", (long)getpid());
  snprintf(missing_path, sizeof(missing_path), "build/missing-%ld.db", (long)getpid());
  memset(byte_seen, 0, sizeof(byte_seen));
  CHECK(textrunsql_pq_dek_generate(dek) == TEXTRUNSQL_PQ_OK);
  for(index = 0; index < sizeof(dek); index++) {
    wrong_dek[index] = (unsigned char)(dek[index] ^ 0xffU);
  }

  CHECK(access(database_path, F_OK) != 0);
  CHECK(access(missing_path, F_OK) != 0);
  CHECK(sqlite3_open_v2(missing_path, &database, SQLITE_OPEN_READWRITE, NULL) == SQLITE_CANTOPEN);
  CHECK(sqlite3_close(database) == SQLITE_OK);
  database = NULL;
  CHECK(access(missing_path, F_OK) != 0);

  CHECK(textrunsql_pq_key_generate(&recipient) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_key_export_public(recipient, public_key, &public_key_len) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_key_import_public(public_key, public_key_len, &public_recipient) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_seal_dek(public_recipient, context, sizeof(context) - 1, dek, envelope, &envelope_len) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_open_dek(recipient, context, sizeof(context) - 1, envelope, envelope_len, opened_dek) == TEXTRUNSQL_PQ_OK);
  CHECK(memcmp(opened_dek, dek, sizeof(dek)) == 0);
  envelope[sizeof(envelope) - 1] ^= 0x01;
  CHECK(textrunsql_pq_open_dek(recipient, context, sizeof(context) - 1, envelope, envelope_len, opened_dek) == TEXTRUNSQL_PQ_ERROR_AUTHENTICATION);
  CHECK(access(missing_path, F_OK) != 0);
  envelope[sizeof(envelope) - 1] ^= 0x01;
  CHECK(textrunsql_pq_open_dek(recipient, context, sizeof(context) - 1, envelope, envelope_len, opened_dek) == TEXTRUNSQL_PQ_OK);

  CHECK(sqlite3_open_v2(database_path, &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK);
  CHECK(textrunsql_pq_key_sqlcipher(database, "main", opened_dek, sizeof(opened_dek), &sqlite_result) == TEXTRUNSQL_PQ_OK);
  CHECK(sqlite_result == SQLITE_OK);
  CHECK(sqlite3_exec(database, "CREATE TABLE protected(value TEXT NOT NULL); INSERT INTO protected VALUES('textrunsql-key-ok');", NULL, NULL, NULL) == SQLITE_OK);
  CHECK(query(database, "PRAGMA cipher_integrity_check;", &query_value) == SQLITE_OK);
  CHECK(query_value.rows == 0);
  CHECK(query(database, "PRAGMA integrity_check;", &query_value) == SQLITE_OK);
  CHECK(query_value.rows == 1 && strcmp(query_value.value, "ok") == 0);
  CHECK(sqlite3_close(database) == SQLITE_OK);
  database = NULL;

  CHECK(sqlite3_open_v2(database_path, &database, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
  CHECK(textrunsql_pq_key_sqlcipher(database, "main", wrong_dek, sizeof(wrong_dek), &sqlite_result) == TEXTRUNSQL_PQ_OK);
  CHECK(query(database, "SELECT value FROM protected;", &query_value) == SQLITE_NOTADB);
  CHECK(sqlite3_close(database) == SQLITE_OK);
  database = NULL;

  CHECK(sqlite3_open_v2(database_path, &database, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
  CHECK(textrunsql_pq_key_sqlcipher(database, "main", dek, sizeof(dek), &sqlite_result) == TEXTRUNSQL_PQ_OK);
  CHECK(query(database, "SELECT value FROM protected;", &query_value) == SQLITE_OK);
  CHECK(query_value.rows == 1 && strcmp(query_value.value, "textrunsql-key-ok") == 0);
  CHECK(sqlite3_close(database) == SQLITE_OK);
  database = NULL;

  make_raw_keyspec(dek, keyspec);
  CHECK(sqlite3_open_v2(database_path, &database, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
  CHECK(sqlite3_key_v2(database, "main", keyspec, 67) == SQLITE_OK);
  CHECK(query(database, "SELECT value FROM protected;", &query_value) == SQLITE_OK);
  CHECK(query_value.rows == 1 && strcmp(query_value.value, "textrunsql-key-ok") == 0);
  CHECK(sqlite3_close(database) == SQLITE_OK);
  database = NULL;

  CHECK(sqlite3_open_v2(database_path, &database, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
  CHECK(sqlite3_key_v2(database, "main", dek, (int)sizeof(dek)) == SQLITE_OK);
  CHECK(query(database, "SELECT value FROM protected;", &query_value) == SQLITE_NOTADB);
  CHECK(sqlite3_close(database) == SQLITE_OK);
  database = NULL;

  for(group = 0; group < 8; group++) {
    snprintf(matrix_path, sizeof(matrix_path), "build/byte-matrix-%ld-%zu.db", (long)getpid(), group);
    CHECK(access(matrix_path, F_OK) != 0);
    for(index = 0; index < sizeof(dek); index++) {
      dek[index] = (unsigned char)((group * sizeof(dek)) + index);
      byte_seen[dek[index]] = 1;
    }
    CHECK(sqlite3_open_v2(matrix_path, &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK);
    CHECK(textrunsql_pq_key_sqlcipher(database, "main", dek, sizeof(dek), &sqlite_result) == TEXTRUNSQL_PQ_OK);
    CHECK(sqlite3_exec(database, "CREATE TABLE protected(value INTEGER NOT NULL); INSERT INTO protected VALUES(1);", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(sqlite3_close(database) == SQLITE_OK);
    database = NULL;
    make_raw_keyspec(dek, keyspec);
    CHECK(sqlite3_open_v2(matrix_path, &database, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK);
    CHECK(sqlite3_key_v2(database, "main", keyspec, 67) == SQLITE_OK);
    CHECK(query(database, "SELECT value FROM protected;", &query_value) == SQLITE_OK);
    CHECK(query_value.rows == 1 && strcmp(query_value.value, "1") == 0);
    CHECK(sqlite3_close(database) == SQLITE_OK);
    database = NULL;
  }
  for(index = 0; index < sizeof(byte_seen); index++) {
    CHECK(byte_seen[index] == 1);
  }

  memset(dek, 0x5a, sizeof(dek));
  dek[0] = 0;
  dek[sizeof(dek) - 1] = 0;
  CHECK(sqlite3_open_v2(":memory:", &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) == SQLITE_OK);
  CHECK(textrunsql_pq_key_sqlcipher(database, "", dek, sizeof(dek), &sqlite_result) == TEXTRUNSQL_PQ_ERROR_MISUSE);
  CHECK(textrunsql_pq_key_sqlcipher(database, "main", dek, sizeof(dek) - 1, &sqlite_result) == TEXTRUNSQL_PQ_ERROR_MISUSE);
  CHECK(textrunsql_pq_key_sqlcipher(database, "main", NULL, sizeof(dek), &sqlite_result) == TEXTRUNSQL_PQ_ERROR_MISUSE);
  CHECK(textrunsql_pq_key_sqlcipher(database, "main", dek, sizeof(dek), NULL) == TEXTRUNSQL_PQ_ERROR_MISUSE);
  CHECK(textrunsql_pq_key_sqlcipher(database, "main", dek, sizeof(dek), &sqlite_result) == TEXTRUNSQL_PQ_OK);
  CHECK(sqlite3_exec(database, "CREATE TABLE zero_ends(value TEXT NOT NULL); INSERT INTO zero_ends VALUES('ok');", NULL, NULL, NULL) == SQLITE_OK);
  CHECK(query(database, "SELECT value FROM zero_ends;", &query_value) == SQLITE_OK);
  CHECK(query_value.rows == 1 && strcmp(query_value.value, "ok") == 0);
  CHECK(sqlite3_close(database) == SQLITE_OK);
  database = NULL;

  CHECK(textrunsql_pq_key_sqlcipher(NULL, "main", dek, sizeof(dek), &sqlite_result) == TEXTRUNSQL_PQ_ERROR_MISUSE);
  result = 0;

cleanup:
  if(database != NULL) {
    sqlite3_close(database);
  }
  memset(dek, 0, sizeof(dek));
  memset(opened_dek, 0, sizeof(opened_dek));
  memset(wrong_dek, 0, sizeof(wrong_dek));
  textrunsql_pq_key_free(public_recipient);
  textrunsql_pq_key_free(recipient);
  if(result == 0) {
    puts("test_keyspec: ok");
  }
  return result;
}
