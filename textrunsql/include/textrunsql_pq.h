#ifndef TEXTRUNSQL_PQ_H
#define TEXTRUNSQL_PQ_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES 1184U
#define TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES 2400U
#define TEXTRUNSQL_PQ_DEK_BYTES 32U
#define TEXTRUNSQL_PQ_RECIPIENT_ID_BYTES 32U
#define TEXTRUNSQL_PQ_CONTEXT_MAX 1024U
#define TEXTRUNSQL_PQ_ENVELOPE_BYTES 1236U

typedef struct textrunsql_pq_key textrunsql_pq_key;
struct sqlite3;

/*
** Results are stable public classes. Provider details are deliberately not
** exposed because they can reveal whether decapsulation or authentication
** rejected an envelope.
*/
typedef enum textrunsql_pq_result {
  TEXTRUNSQL_PQ_OK = 0,
  TEXTRUNSQL_PQ_ERROR_MISUSE = 1,
  TEXTRUNSQL_PQ_ERROR_BUFFER_TOO_SMALL = 2,
  TEXTRUNSQL_PQ_ERROR_UNSUPPORTED = 3,
  TEXTRUNSQL_PQ_ERROR_ALLOCATION = 4,
  TEXTRUNSQL_PQ_ERROR_FORMAT = 5,
  TEXTRUNSQL_PQ_ERROR_AUTHENTICATION = 6,
  TEXTRUNSQL_PQ_ERROR_CRYPTO = 7,
  TEXTRUNSQL_PQ_ERROR_SQLCIPHER = 8
} textrunsql_pq_result;

/*
** Keys are immutable opaque objects. A caller owns each returned key and
** releases it with textrunsql_pq_key_free(). Independent key objects may be
** used concurrently; access to the same object must be externally serialized.
**
** Export functions use a size-query convention: pass a NULL output to obtain
** the required length. Private-key output belongs to the caller and must be
** wiped after use.
*/
int textrunsql_pq_key_generate(textrunsql_pq_key **key_out);
int textrunsql_pq_key_import_public(const uint8_t *public_key, size_t public_key_len, textrunsql_pq_key **key_out);
int textrunsql_pq_key_import_private(const uint8_t *public_key, size_t public_key_len, const uint8_t *private_key, size_t private_key_len, textrunsql_pq_key **key_out);
int textrunsql_pq_key_export_public(const textrunsql_pq_key *key, uint8_t *public_key_out, size_t *public_key_len);
int textrunsql_pq_key_export_private(const textrunsql_pq_key *key, uint8_t *private_key_out, size_t *private_key_len);
void textrunsql_pq_key_free(textrunsql_pq_key *key);

/* Generate a database encryption key with the configured OpenSSL random source. */
int textrunsql_pq_dek_generate(uint8_t dek_out[TEXTRUNSQL_PQ_DEK_BYTES]);

/*
** A context is a nonempty, application-defined stable database identifier.
** Seal accepts either a public or private recipient key. Open requires the
** matching private key and writes a DEK only after full authentication.
** envelope_out and dek_out are caller-owned; both may overlap their inputs.
*/
int textrunsql_pq_seal_dek(const textrunsql_pq_key *recipient, const uint8_t *context, size_t context_len, const uint8_t dek[TEXTRUNSQL_PQ_DEK_BYTES], uint8_t *envelope_out, size_t *envelope_len);
int textrunsql_pq_open_dek(const textrunsql_pq_key *recipient, const uint8_t *context, size_t context_len, const uint8_t *envelope, size_t envelope_len, uint8_t dek_out[TEXTRUNSQL_PQ_DEK_BYTES]);

/*
** Apply exactly 32 DEK bytes to a caller-opened SQLCipher schema through the
** public raw-key syntax. Call this before any schema or page access. Success
** sets the key but does not authenticate existing database content; the caller
** must read protected content and run integrity checks. sqlite_result receives
** the direct SQLite result.
*/
int textrunsql_pq_key_sqlcipher(struct sqlite3 *db, const char *schema, const uint8_t *dek, size_t dek_len, int *sqlite_result);

const char *textrunsql_pq_result_string(int result);

#ifdef __cplusplus
}
#endif

#endif
