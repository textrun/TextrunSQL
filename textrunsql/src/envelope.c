#include "internal.h"

#include <openssl/crypto.h>

#include <stdlib.h>
#include <string.h>

#define TEXTRUNSQL_PQ_OFFSET_VERSION 8U
#define TEXTRUNSQL_PQ_OFFSET_SUITE 10U
#define TEXTRUNSQL_PQ_OFFSET_FLAGS 12U
#define TEXTRUNSQL_PQ_OFFSET_RESERVED 14U
#define TEXTRUNSQL_PQ_OFFSET_TOTAL_LENGTH 16U
#define TEXTRUNSQL_PQ_OFFSET_KEM_CIPHERTEXT_LENGTH 20U
#define TEXTRUNSQL_PQ_OFFSET_WRAPPED_DEK_LENGTH 22U
#define TEXTRUNSQL_PQ_OFFSET_RECIPIENT_ID 24U
#define TEXTRUNSQL_PQ_OFFSET_CONTEXT_HASH 56U
#define TEXTRUNSQL_PQ_OFFSET_KEM_CIPHERTEXT 88U
#define TEXTRUNSQL_PQ_OFFSET_NONCE 1176U
#define TEXTRUNSQL_PQ_OFFSET_WRAPPED_DEK 1188U
#define TEXTRUNSQL_PQ_OFFSET_TAG 1220U

static const unsigned char textrunsql_pq_magic[8] = {'T', 'R', 'S', 'Q', 'L', 'P', 'Q', 0};

static void textrunsql_store_u16(unsigned char *output, unsigned int value) {
  output[0] = (unsigned char)((value >> 8) & 0xff);
  output[1] = (unsigned char)(value & 0xff);
}

static void textrunsql_store_u32(unsigned char *output, unsigned long value) {
  output[0] = (unsigned char)((value >> 24) & 0xff);
  output[1] = (unsigned char)((value >> 16) & 0xff);
  output[2] = (unsigned char)((value >> 8) & 0xff);
  output[3] = (unsigned char)(value & 0xff);
}

static unsigned int textrunsql_load_u16(const unsigned char *input) {
  return ((unsigned int)input[0] << 8) | input[1];
}

static unsigned long textrunsql_load_u32(const unsigned char *input) {
  return ((unsigned long)input[0] << 24) | ((unsigned long)input[1] << 16) | ((unsigned long)input[2] << 8) | input[3];
}

static int textrunsql_validate_context(const unsigned char *context, size_t context_len) {
  if(context == NULL || context_len == 0 || context_len > TEXTRUNSQL_PQ_CONTEXT_MAX) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  return TEXTRUNSQL_PQ_OK;
}

static int textrunsql_key_create(EVP_PKEY *provider_key, int has_private, textrunsql_pq_key **key_out) {
  textrunsql_pq_key *key;
  int result;

  if(provider_key == NULL || key_out == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  *key_out = NULL;
#ifdef TEXTRUNSQL_TESTING
  if(textrunsql_test_fail_consume(TEXTRUNSQL_TEST_FAIL_KEY_ALLOCATION)) {
    EVP_PKEY_free(provider_key);
    return TEXTRUNSQL_PQ_ERROR_ALLOCATION;
  }
#endif
  key = OPENSSL_zalloc(sizeof(*key));
  if(key == NULL) {
    EVP_PKEY_free(provider_key);
    return TEXTRUNSQL_PQ_ERROR_ALLOCATION;
  }
  key->pkey = provider_key;
  key->has_private = has_private;
  result = textrunsql_provider_key_export_public(key->pkey, key->public_key);
  if(result != TEXTRUNSQL_PQ_OK) {
    textrunsql_pq_key_free(key);
    return result;
  }
  *key_out = key;
  return TEXTRUNSQL_PQ_OK;
}

int textrunsql_pq_key_generate(textrunsql_pq_key **key_out) {
  EVP_PKEY *provider_key = NULL;
  int result;

  if(key_out == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  *key_out = NULL;
  result = textrunsql_provider_key_generate(NULL, 0, &provider_key);
  if(result != TEXTRUNSQL_PQ_OK) {
    return result;
  }
  return textrunsql_key_create(provider_key, 1, key_out);
}

int textrunsql_pq_key_import_public(const uint8_t *public_key, size_t public_key_len, textrunsql_pq_key **key_out) {
  EVP_PKEY *provider_key = NULL;
  int result;

  if(key_out == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  *key_out = NULL;
  result = textrunsql_provider_key_import(public_key, public_key_len, NULL, 0, &provider_key);
  if(result != TEXTRUNSQL_PQ_OK) {
    return result;
  }
  return textrunsql_key_create(provider_key, 0, key_out);
}

int textrunsql_pq_key_import_private(const uint8_t *public_key, size_t public_key_len, const uint8_t *private_key, size_t private_key_len, textrunsql_pq_key **key_out) {
  EVP_PKEY *provider_key = NULL;
  int result;

  if(key_out == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  *key_out = NULL;
  result = textrunsql_provider_key_import(public_key, public_key_len, private_key, private_key_len, &provider_key);
  if(result != TEXTRUNSQL_PQ_OK) {
    return result;
  }
  return textrunsql_key_create(provider_key, 1, key_out);
}

int textrunsql_pq_key_export_public(const textrunsql_pq_key *key, uint8_t *public_key_out, size_t *public_key_len) {
  if(key == NULL || public_key_len == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  if(public_key_out == NULL) {
    *public_key_len = TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES;
    return TEXTRUNSQL_PQ_OK;
  }
  if(*public_key_len < TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES) {
    *public_key_len = TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES;
    return TEXTRUNSQL_PQ_ERROR_BUFFER_TOO_SMALL;
  }
  memcpy(public_key_out, key->public_key, TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES);
  *public_key_len = TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES;
  return TEXTRUNSQL_PQ_OK;
}

int textrunsql_pq_key_export_private(const textrunsql_pq_key *key, uint8_t *private_key_out, size_t *private_key_len) {
  int result;

  if(key == NULL || private_key_len == NULL || !key->has_private) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  if(private_key_out == NULL) {
    *private_key_len = TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES;
    return TEXTRUNSQL_PQ_OK;
  }
  if(*private_key_len < TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES) {
    *private_key_len = TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES;
    return TEXTRUNSQL_PQ_ERROR_BUFFER_TOO_SMALL;
  }
  result = textrunsql_provider_key_export_private(key->pkey, private_key_out);
  if(result == TEXTRUNSQL_PQ_OK) {
    *private_key_len = TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES;
  } else {
    *private_key_len = 0;
  }
  return result;
}

void textrunsql_pq_key_free(textrunsql_pq_key *key) {
  if(key != NULL) {
    EVP_PKEY_free(key->pkey);
    OPENSSL_cleanse(key, sizeof(*key));
    OPENSSL_free(key);
  }
}

int textrunsql_pq_dek_generate(uint8_t dek_out[TEXTRUNSQL_PQ_DEK_BYTES]) {
  if(dek_out == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  memset(dek_out, 0, TEXTRUNSQL_PQ_DEK_BYTES);
  return textrunsql_provider_random(dek_out, TEXTRUNSQL_PQ_DEK_BYTES);
}

static int textrunsql_seal_dek_internal(const textrunsql_pq_key *recipient, const unsigned char *context, size_t context_len, const unsigned char dek[TEXTRUNSQL_PQ_DEK_BYTES], const unsigned char *test_ikme, size_t test_ikme_len, const unsigned char *test_nonce, unsigned char envelope_out[TEXTRUNSQL_PQ_ENVELOPE_BYTES]) {
  unsigned char envelope[TEXTRUNSQL_PQ_ENVELOPE_BYTES];
  unsigned char shared_secret[TEXTRUNSQL_PQ_SHARED_SECRET_BYTES];
  unsigned char key_encryption_key[32];
  int result;

  memset(envelope, 0, sizeof(envelope));
  memset(shared_secret, 0, sizeof(shared_secret));
  memset(key_encryption_key, 0, sizeof(key_encryption_key));
  memcpy(envelope, textrunsql_pq_magic, sizeof(textrunsql_pq_magic));
  textrunsql_store_u16(envelope + TEXTRUNSQL_PQ_OFFSET_VERSION, 1);
  textrunsql_store_u16(envelope + TEXTRUNSQL_PQ_OFFSET_SUITE, 1);
  textrunsql_store_u16(envelope + TEXTRUNSQL_PQ_OFFSET_FLAGS, 0);
  textrunsql_store_u16(envelope + TEXTRUNSQL_PQ_OFFSET_RESERVED, 0);
  textrunsql_store_u32(envelope + TEXTRUNSQL_PQ_OFFSET_TOTAL_LENGTH, TEXTRUNSQL_PQ_ENVELOPE_BYTES);
  textrunsql_store_u16(envelope + TEXTRUNSQL_PQ_OFFSET_KEM_CIPHERTEXT_LENGTH, TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES);
  textrunsql_store_u16(envelope + TEXTRUNSQL_PQ_OFFSET_WRAPPED_DEK_LENGTH, TEXTRUNSQL_PQ_DEK_BYTES);
  result = textrunsql_provider_sha256(recipient->public_key, TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES, envelope + TEXTRUNSQL_PQ_OFFSET_RECIPIENT_ID);
  if(result != TEXTRUNSQL_PQ_OK) {
    goto cleanup;
  }
  result = textrunsql_provider_sha256(context, context_len, envelope + TEXTRUNSQL_PQ_OFFSET_CONTEXT_HASH);
  if(result != TEXTRUNSQL_PQ_OK) {
    goto cleanup;
  }
  result = textrunsql_provider_encapsulate(recipient->pkey, test_ikme, test_ikme_len, envelope + TEXTRUNSQL_PQ_OFFSET_KEM_CIPHERTEXT, shared_secret);
  if(result != TEXTRUNSQL_PQ_OK) {
    goto cleanup;
  }
  if(test_nonce != NULL) {
    memcpy(envelope + TEXTRUNSQL_PQ_OFFSET_NONCE, test_nonce, TEXTRUNSQL_PQ_NONCE_BYTES);
  } else {
    result = textrunsql_provider_random(envelope + TEXTRUNSQL_PQ_OFFSET_NONCE, TEXTRUNSQL_PQ_NONCE_BYTES);
    if(result != TEXTRUNSQL_PQ_OK) {
      goto cleanup;
    }
  }
  result = textrunsql_provider_hkdf(shared_secret, envelope + TEXTRUNSQL_PQ_OFFSET_CONTEXT_HASH, key_encryption_key);
  if(result != TEXTRUNSQL_PQ_OK) {
    goto cleanup;
  }
  result = textrunsql_provider_aead_encrypt(key_encryption_key, envelope + TEXTRUNSQL_PQ_OFFSET_NONCE, envelope, TEXTRUNSQL_PQ_OFFSET_WRAPPED_DEK, dek, envelope + TEXTRUNSQL_PQ_OFFSET_WRAPPED_DEK, envelope + TEXTRUNSQL_PQ_OFFSET_TAG);
  if(result != TEXTRUNSQL_PQ_OK) {
    goto cleanup;
  }
  memcpy(envelope_out, envelope, sizeof(envelope));

cleanup:
  OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
  OPENSSL_cleanse(key_encryption_key, sizeof(key_encryption_key));
  OPENSSL_cleanse(envelope, sizeof(envelope));
  return result;
}

int textrunsql_pq_seal_dek(const textrunsql_pq_key *recipient, const uint8_t *context, size_t context_len, const uint8_t dek[TEXTRUNSQL_PQ_DEK_BYTES], uint8_t *envelope_out, size_t *envelope_len) {
  int result;

  if(recipient == NULL || recipient->pkey == NULL || dek == NULL || envelope_len == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  result = textrunsql_validate_context(context, context_len);
  if(result != TEXTRUNSQL_PQ_OK) {
    return result;
  }
  if(envelope_out == NULL) {
    *envelope_len = TEXTRUNSQL_PQ_ENVELOPE_BYTES;
    return TEXTRUNSQL_PQ_OK;
  }
  if(*envelope_len < TEXTRUNSQL_PQ_ENVELOPE_BYTES) {
    *envelope_len = TEXTRUNSQL_PQ_ENVELOPE_BYTES;
    return TEXTRUNSQL_PQ_ERROR_BUFFER_TOO_SMALL;
  }
  memset(envelope_out, 0, TEXTRUNSQL_PQ_ENVELOPE_BYTES);
  result = textrunsql_seal_dek_internal(recipient, context, context_len, dek, NULL, 0, NULL, envelope_out);
  if(result == TEXTRUNSQL_PQ_OK) {
    *envelope_len = TEXTRUNSQL_PQ_ENVELOPE_BYTES;
  } else {
    *envelope_len = 0;
  }
  return result;
}

int textrunsql_pq_open_dek(const textrunsql_pq_key *recipient, const uint8_t *context, size_t context_len, const uint8_t *envelope, size_t envelope_len, uint8_t dek_out[TEXTRUNSQL_PQ_DEK_BYTES]) {
  unsigned char recipient_id[32];
  unsigned char context_hash[32];
  unsigned char shared_secret[TEXTRUNSQL_PQ_SHARED_SECRET_BYTES];
  unsigned char key_encryption_key[32];
  unsigned char candidate_dek[TEXTRUNSQL_PQ_DEK_BYTES];
  int result = TEXTRUNSQL_PQ_ERROR_FORMAT;

  if(recipient == NULL || recipient->pkey == NULL || !recipient->has_private || envelope == NULL || dek_out == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  memset(dek_out, 0, TEXTRUNSQL_PQ_DEK_BYTES);
  memset(recipient_id, 0, sizeof(recipient_id));
  memset(context_hash, 0, sizeof(context_hash));
  memset(shared_secret, 0, sizeof(shared_secret));
  memset(key_encryption_key, 0, sizeof(key_encryption_key));
  memset(candidate_dek, 0, sizeof(candidate_dek));
  result = textrunsql_validate_context(context, context_len);
  if(result != TEXTRUNSQL_PQ_OK) {
    goto cleanup;
  }
  if(envelope_len != TEXTRUNSQL_PQ_ENVELOPE_BYTES || CRYPTO_memcmp(envelope, textrunsql_pq_magic, sizeof(textrunsql_pq_magic)) != 0 || textrunsql_load_u16(envelope + TEXTRUNSQL_PQ_OFFSET_FLAGS) != 0 || textrunsql_load_u16(envelope + TEXTRUNSQL_PQ_OFFSET_RESERVED) != 0 || textrunsql_load_u32(envelope + TEXTRUNSQL_PQ_OFFSET_TOTAL_LENGTH) != TEXTRUNSQL_PQ_ENVELOPE_BYTES || textrunsql_load_u16(envelope + TEXTRUNSQL_PQ_OFFSET_KEM_CIPHERTEXT_LENGTH) != TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES || textrunsql_load_u16(envelope + TEXTRUNSQL_PQ_OFFSET_WRAPPED_DEK_LENGTH) != TEXTRUNSQL_PQ_DEK_BYTES) {
    result = TEXTRUNSQL_PQ_ERROR_FORMAT;
    goto cleanup;
  }
  if(textrunsql_load_u16(envelope + TEXTRUNSQL_PQ_OFFSET_VERSION) != 1 || textrunsql_load_u16(envelope + TEXTRUNSQL_PQ_OFFSET_SUITE) != 1) {
    result = TEXTRUNSQL_PQ_ERROR_UNSUPPORTED;
    goto cleanup;
  }
  result = textrunsql_provider_sha256(recipient->public_key, TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES, recipient_id);
  if(result != TEXTRUNSQL_PQ_OK) {
    goto cleanup;
  }
  result = textrunsql_provider_sha256(context, context_len, context_hash);
  if(result != TEXTRUNSQL_PQ_OK) {
    goto cleanup;
  }
  if(CRYPTO_memcmp(recipient_id, envelope + TEXTRUNSQL_PQ_OFFSET_RECIPIENT_ID, sizeof(recipient_id)) != 0 || CRYPTO_memcmp(context_hash, envelope + TEXTRUNSQL_PQ_OFFSET_CONTEXT_HASH, sizeof(context_hash)) != 0) {
    result = TEXTRUNSQL_PQ_ERROR_AUTHENTICATION;
    goto cleanup;
  }
  result = textrunsql_provider_decapsulate(recipient->pkey, envelope + TEXTRUNSQL_PQ_OFFSET_KEM_CIPHERTEXT, shared_secret);
  if(result != TEXTRUNSQL_PQ_OK) {
    result = TEXTRUNSQL_PQ_ERROR_AUTHENTICATION;
    goto cleanup;
  }
  result = textrunsql_provider_hkdf(shared_secret, context_hash, key_encryption_key);
  if(result != TEXTRUNSQL_PQ_OK) {
    goto cleanup;
  }
  result = textrunsql_provider_aead_decrypt(key_encryption_key, envelope + TEXTRUNSQL_PQ_OFFSET_NONCE, envelope, TEXTRUNSQL_PQ_OFFSET_WRAPPED_DEK, envelope + TEXTRUNSQL_PQ_OFFSET_WRAPPED_DEK, envelope + TEXTRUNSQL_PQ_OFFSET_TAG, candidate_dek);
  if(result != TEXTRUNSQL_PQ_OK) {
    result = TEXTRUNSQL_PQ_ERROR_AUTHENTICATION;
    goto cleanup;
  }
  memcpy(dek_out, candidate_dek, TEXTRUNSQL_PQ_DEK_BYTES);

cleanup:
  OPENSSL_cleanse(recipient_id, sizeof(recipient_id));
  OPENSSL_cleanse(context_hash, sizeof(context_hash));
  OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
  OPENSSL_cleanse(key_encryption_key, sizeof(key_encryption_key));
  OPENSSL_cleanse(candidate_dek, sizeof(candidate_dek));
  return result;
}

const char *textrunsql_pq_result_string(int result) {
  switch(result) {
    case TEXTRUNSQL_PQ_OK:
      return "success";
    case TEXTRUNSQL_PQ_ERROR_MISUSE:
      return "invalid API use";
    case TEXTRUNSQL_PQ_ERROR_BUFFER_TOO_SMALL:
      return "output buffer too small";
    case TEXTRUNSQL_PQ_ERROR_UNSUPPORTED:
      return "unsupported algorithm, provider, or format";
    case TEXTRUNSQL_PQ_ERROR_ALLOCATION:
      return "allocation failed";
    case TEXTRUNSQL_PQ_ERROR_FORMAT:
      return "invalid envelope format";
    case TEXTRUNSQL_PQ_ERROR_AUTHENTICATION:
      return "recipient, context, or envelope authentication failed";
    case TEXTRUNSQL_PQ_ERROR_CRYPTO:
      return "cryptographic operation failed";
    case TEXTRUNSQL_PQ_ERROR_SQLCIPHER:
      return "SQLCipher rejected the key";
    default:
      return "unknown TextrunSQL result";
  }
}

#ifdef TEXTRUNSQL_TESTING
int textrunsql_pq_test_key_from_seed(const uint8_t seed[64], textrunsql_pq_key **key_out) {
  EVP_PKEY *provider_key = NULL;
  int result;

  if(seed == NULL || key_out == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  *key_out = NULL;
  result = textrunsql_provider_key_generate(seed, 64, &provider_key);
  if(result != TEXTRUNSQL_PQ_OK) {
    return result;
  }
  return textrunsql_key_create(provider_key, 1, key_out);
}

int textrunsql_pq_test_seal_dek(const textrunsql_pq_key *recipient, const uint8_t *context, size_t context_len, const uint8_t dek[TEXTRUNSQL_PQ_DEK_BYTES], const uint8_t ikme[32], const uint8_t nonce[TEXTRUNSQL_PQ_NONCE_BYTES], uint8_t envelope_out[TEXTRUNSQL_PQ_ENVELOPE_BYTES]) {
  int result;

  if(recipient == NULL || recipient->pkey == NULL || dek == NULL || ikme == NULL || nonce == NULL || envelope_out == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  result = textrunsql_validate_context(context, context_len);
  if(result != TEXTRUNSQL_PQ_OK) {
    return result;
  }
  return textrunsql_seal_dek_internal(recipient, context, context_len, dek, ikme, 32, nonce, envelope_out);
}
#endif
