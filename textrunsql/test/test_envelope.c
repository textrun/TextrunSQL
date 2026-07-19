#include "internal.h"

#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>

#define CHECK(expression) do { if(!(expression)) { fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expression); goto cleanup; } } while(0)

static int all_zero(const unsigned char *bytes, size_t length) {
  size_t index;
  unsigned char combined = 0;

  for(index = 0; index < length; index++) {
    combined |= bytes[index];
  }
  return combined == 0;
}

int main(void) {
  static const unsigned char context[] = "customer/database/00000001";
  static const unsigned char wrong_context[] = "customer/database/00000002";
  textrunsql_pq_key *generated = NULL;
  textrunsql_pq_key *public_only = NULL;
  textrunsql_pq_key *imported = NULL;
  textrunsql_pq_key *rejected = NULL;
  textrunsql_pq_key *wrong_recipient = NULL;
  unsigned char public_key[TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES];
  unsigned char private_key[TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES];
  unsigned char dek[TEXTRUNSQL_PQ_DEK_BYTES];
  unsigned char opened_dek[TEXTRUNSQL_PQ_DEK_BYTES];
  unsigned char envelope[TEXTRUNSQL_PQ_ENVELOPE_BYTES + 1];
  unsigned char tampered[TEXTRUNSQL_PQ_ENVELOPE_BYTES];
  unsigned char maximum_context[TEXTRUNSQL_PQ_CONTEXT_MAX + 1];
  size_t public_key_len = 0;
  size_t private_key_len = 0;
  size_t envelope_len = 0;
  size_t index;
  int result = 1;

  for(index = 0; index < sizeof(dek); index++) {
    dek[index] = (unsigned char)((index * 17U) ^ 0xa5U);
  }
  CHECK(textrunsql_pq_dek_generate(opened_dek) == TEXTRUNSQL_PQ_OK);
  CHECK(!all_zero(opened_dek, sizeof(opened_dek)));
  memset(opened_dek, 0xa5, sizeof(opened_dek));
  textrunsql_test_fail_next(TEXTRUNSQL_TEST_FAIL_RANDOM);
  CHECK(textrunsql_pq_dek_generate(opened_dek) == TEXTRUNSQL_PQ_ERROR_CRYPTO);
  CHECK(all_zero(opened_dek, sizeof(opened_dek)));
  memset(maximum_context, 0x42, sizeof(maximum_context));
  CHECK(textrunsql_pq_key_generate(&generated) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_key_generate(&wrong_recipient) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_key_export_public(generated, NULL, &public_key_len) == TEXTRUNSQL_PQ_OK);
  CHECK(public_key_len == sizeof(public_key));
  CHECK(textrunsql_pq_key_export_public(generated, public_key, &public_key_len) == TEXTRUNSQL_PQ_OK);
  public_key_len--;
  CHECK(textrunsql_pq_key_export_public(generated, public_key, &public_key_len) == TEXTRUNSQL_PQ_ERROR_BUFFER_TOO_SMALL);
  CHECK(public_key_len == sizeof(public_key));
  CHECK(textrunsql_pq_key_export_private(generated, NULL, &private_key_len) == TEXTRUNSQL_PQ_OK);
  CHECK(private_key_len == sizeof(private_key));
  CHECK(textrunsql_pq_key_export_private(generated, private_key, &private_key_len) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_key_import_public(public_key, public_key_len, &public_only) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_key_import_private(public_key, public_key_len, private_key, private_key_len, &imported) == TEXTRUNSQL_PQ_OK);
  public_key[0] ^= 0x01;
  CHECK(textrunsql_pq_key_import_private(public_key, public_key_len, private_key, private_key_len, &rejected) == TEXTRUNSQL_PQ_ERROR_CRYPTO);
  CHECK(rejected == NULL);
  public_key[0] ^= 0x01;
  CHECK(textrunsql_pq_key_export_private(public_only, private_key, &private_key_len) == TEXTRUNSQL_PQ_ERROR_MISUSE);

  CHECK(textrunsql_pq_seal_dek(public_only, context, sizeof(context) - 1, dek, NULL, &envelope_len) == TEXTRUNSQL_PQ_OK);
  CHECK(envelope_len == TEXTRUNSQL_PQ_ENVELOPE_BYTES);
  envelope_len--;
  CHECK(textrunsql_pq_seal_dek(public_only, context, sizeof(context) - 1, dek, envelope, &envelope_len) == TEXTRUNSQL_PQ_ERROR_BUFFER_TOO_SMALL);
  CHECK(envelope_len == TEXTRUNSQL_PQ_ENVELOPE_BYTES);
  CHECK(textrunsql_pq_seal_dek(public_only, context, sizeof(context) - 1, dek, envelope, &envelope_len) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_open_dek(imported, context, sizeof(context) - 1, envelope, envelope_len, opened_dek) == TEXTRUNSQL_PQ_OK);
  CHECK(CRYPTO_memcmp(opened_dek, dek, sizeof(dek)) == 0);
  envelope_len = TEXTRUNSQL_PQ_ENVELOPE_BYTES;
  CHECK(textrunsql_pq_seal_dek(public_only, maximum_context, TEXTRUNSQL_PQ_CONTEXT_MAX - 1, dek, tampered, &envelope_len) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_open_dek(imported, maximum_context, TEXTRUNSQL_PQ_CONTEXT_MAX - 1, tampered, envelope_len, opened_dek) == TEXTRUNSQL_PQ_OK);
  envelope_len = TEXTRUNSQL_PQ_ENVELOPE_BYTES;
  CHECK(textrunsql_pq_seal_dek(public_only, maximum_context, TEXTRUNSQL_PQ_CONTEXT_MAX, dek, tampered, &envelope_len) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_open_dek(imported, maximum_context, TEXTRUNSQL_PQ_CONTEXT_MAX, tampered, envelope_len, opened_dek) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_seal_dek(public_only, maximum_context, TEXTRUNSQL_PQ_CONTEXT_MAX + 1, dek, tampered, &envelope_len) == TEXTRUNSQL_PQ_ERROR_MISUSE);

  memset(opened_dek, 0xa5, sizeof(opened_dek));
  CHECK(textrunsql_pq_open_dek(imported, wrong_context, sizeof(wrong_context) - 1, envelope, envelope_len, opened_dek) == TEXTRUNSQL_PQ_ERROR_AUTHENTICATION);
  CHECK(all_zero(opened_dek, sizeof(opened_dek)));
  memset(opened_dek, 0xa5, sizeof(opened_dek));
  CHECK(textrunsql_pq_open_dek(wrong_recipient, context, sizeof(context) - 1, envelope, envelope_len, opened_dek) == TEXTRUNSQL_PQ_ERROR_AUTHENTICATION);
  CHECK(all_zero(opened_dek, sizeof(opened_dek)));

  memcpy(tampered, envelope, sizeof(tampered));
  tampered[9] ^= 0x01;
  CHECK(textrunsql_pq_open_dek(imported, context, sizeof(context) - 1, tampered, sizeof(tampered), opened_dek) == TEXTRUNSQL_PQ_ERROR_UNSUPPORTED);
  memcpy(tampered, envelope, sizeof(tampered));
  tampered[11] ^= 0x01;
  CHECK(textrunsql_pq_open_dek(imported, context, sizeof(context) - 1, tampered, sizeof(tampered), opened_dek) == TEXTRUNSQL_PQ_ERROR_UNSUPPORTED);
  memcpy(tampered, envelope, sizeof(tampered));
  tampered[13] = 1;
  CHECK(textrunsql_pq_open_dek(imported, context, sizeof(context) - 1, tampered, sizeof(tampered), opened_dek) == TEXTRUNSQL_PQ_ERROR_FORMAT);
  memcpy(tampered, envelope, sizeof(tampered));
  memset(tampered + 16, 0xff, 4);
  CHECK(textrunsql_pq_open_dek(imported, context, sizeof(context) - 1, tampered, sizeof(tampered), opened_dek) == TEXTRUNSQL_PQ_ERROR_FORMAT);
  memcpy(tampered, envelope, sizeof(tampered));
  tampered[1220] ^= 0x01;
  CHECK(textrunsql_pq_open_dek(imported, context, sizeof(context) - 1, tampered, sizeof(tampered), opened_dek) == TEXTRUNSQL_PQ_ERROR_AUTHENTICATION);
  textrunsql_test_fail_next(TEXTRUNSQL_TEST_FAIL_KEM);
  memset(opened_dek, 0xa5, sizeof(opened_dek));
  CHECK(textrunsql_pq_open_dek(imported, context, sizeof(context) - 1, envelope, envelope_len, opened_dek) == TEXTRUNSQL_PQ_ERROR_AUTHENTICATION);
  CHECK(all_zero(opened_dek, sizeof(opened_dek)));

  for(index = 0; index < TEXTRUNSQL_PQ_ENVELOPE_BYTES; index++) {
    memcpy(tampered, envelope, sizeof(tampered));
    tampered[index] ^= 0x01;
    memset(opened_dek, 0xa5, sizeof(opened_dek));
    CHECK(textrunsql_pq_open_dek(imported, context, sizeof(context) - 1, tampered, sizeof(tampered), opened_dek) != TEXTRUNSQL_PQ_OK);
    CHECK(all_zero(opened_dek, sizeof(opened_dek)));
  }
  for(index = 0; index < TEXTRUNSQL_PQ_ENVELOPE_BYTES; index++) {
    CHECK(textrunsql_pq_open_dek(imported, context, sizeof(context) - 1, envelope, index, opened_dek) == TEXTRUNSQL_PQ_ERROR_FORMAT);
  }
  envelope[TEXTRUNSQL_PQ_ENVELOPE_BYTES] = 0;
  CHECK(textrunsql_pq_open_dek(imported, context, sizeof(context) - 1, envelope, sizeof(envelope), opened_dek) == TEXTRUNSQL_PQ_ERROR_FORMAT);
  CHECK(textrunsql_pq_seal_dek(public_only, NULL, 0, dek, envelope, &envelope_len) == TEXTRUNSQL_PQ_ERROR_MISUSE);
  CHECK(textrunsql_pq_open_dek(public_only, context, sizeof(context) - 1, envelope, TEXTRUNSQL_PQ_ENVELOPE_BYTES, opened_dek) == TEXTRUNSQL_PQ_ERROR_MISUSE);
  for(index = TEXTRUNSQL_TEST_FAIL_KEM; index <= TEXTRUNSQL_TEST_FAIL_AEAD; index++) {
    memset(envelope, 0xa5, TEXTRUNSQL_PQ_ENVELOPE_BYTES);
    envelope_len = TEXTRUNSQL_PQ_ENVELOPE_BYTES;
    textrunsql_test_fail_next((textrunsql_test_failpoint)index);
    CHECK(textrunsql_pq_seal_dek(public_only, context, sizeof(context) - 1, dek, envelope, &envelope_len) != TEXTRUNSQL_PQ_OK);
    CHECK(envelope_len == 0);
    CHECK(all_zero(envelope, TEXTRUNSQL_PQ_ENVELOPE_BYTES));
  }
  textrunsql_test_fail_next(TEXTRUNSQL_TEST_FAIL_KEY_ALLOCATION);
  CHECK(textrunsql_pq_key_import_public(public_key, public_key_len, &rejected) == TEXTRUNSQL_PQ_ERROR_ALLOCATION);
  CHECK(rejected == NULL);
  CHECK(strcmp(textrunsql_pq_result_string(TEXTRUNSQL_PQ_OK), "success") == 0);
  result = 0;

cleanup:
  OPENSSL_cleanse(private_key, sizeof(private_key));
  OPENSSL_cleanse(dek, sizeof(dek));
  OPENSSL_cleanse(opened_dek, sizeof(opened_dek));
  OPENSSL_cleanse(envelope, sizeof(envelope));
  OPENSSL_cleanse(tampered, sizeof(tampered));
  OPENSSL_cleanse(maximum_context, sizeof(maximum_context));
  textrunsql_pq_key_free(wrong_recipient);
  textrunsql_pq_key_free(rejected);
  textrunsql_pq_key_free(imported);
  textrunsql_pq_key_free(public_only);
  textrunsql_pq_key_free(generated);
  if(result == 0) {
    puts("test_envelope: ok");
  }
  return result;
}
