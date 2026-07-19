#include "internal.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#include <limits.h>
#include <string.h>

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "TextrunSQL requires OpenSSL 3.5 or later for ML-KEM"
#endif

#ifdef TEXTRUNSQL_TESTING
static textrunsql_test_failpoint textrunsql_test_pending_failpoint;

void textrunsql_test_fail_next(textrunsql_test_failpoint failpoint) {
  textrunsql_test_pending_failpoint = failpoint;
}

int textrunsql_test_fail_consume(textrunsql_test_failpoint failpoint) {
  if(textrunsql_test_pending_failpoint == failpoint) {
    textrunsql_test_pending_failpoint = TEXTRUNSQL_TEST_FAIL_NONE;
    return 1;
  }
  return 0;
}
#endif

static int textrunsql_provider_failure(int result) {
  ERR_clear_error();
  return result;
}

int textrunsql_provider_key_generate(const unsigned char *seed, size_t seed_len, EVP_PKEY **key_out) {
  EVP_PKEY_CTX *context = NULL;
  EVP_PKEY *key = NULL;
  OSSL_PARAM params[2];
  int result = TEXTRUNSQL_PQ_ERROR_CRYPTO;

  if(key_out == NULL || (seed == NULL && seed_len != 0) || (seed != NULL && seed_len != 64)) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  *key_out = NULL;
  ERR_clear_error();
  context = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
  if(context == NULL) {
    result = TEXTRUNSQL_PQ_ERROR_UNSUPPORTED;
    goto cleanup;
  }
  if(EVP_PKEY_keygen_init(context) <= 0) {
    goto cleanup;
  }
  if(seed != NULL) {
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, (void *)seed, seed_len);
    params[1] = OSSL_PARAM_construct_end();
    if(EVP_PKEY_CTX_set_params(context, params) <= 0) {
      goto cleanup;
    }
  }
  if(EVP_PKEY_generate(context, &key) <= 0) {
    goto cleanup;
  }
  *key_out = key;
  key = NULL;
  result = TEXTRUNSQL_PQ_OK;

cleanup:
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(context);
  return result == TEXTRUNSQL_PQ_OK ? result : textrunsql_provider_failure(result);
}

int textrunsql_provider_key_import(const unsigned char *public_key, size_t public_key_len, const unsigned char *private_key, size_t private_key_len, EVP_PKEY **key_out) {
  EVP_PKEY_CTX *context = NULL;
  EVP_PKEY *key = NULL;
  OSSL_PARAM params[3];
  EVP_PKEY_CTX *validation_context = NULL;
  int selection;
  int result = TEXTRUNSQL_PQ_ERROR_CRYPTO;

  if(public_key == NULL || public_key_len != TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES || key_out == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  if((private_key == NULL && private_key_len != 0) || (private_key != NULL && private_key_len != TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES)) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  *key_out = NULL;
  ERR_clear_error();
  context = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
  if(context == NULL) {
    result = TEXTRUNSQL_PQ_ERROR_UNSUPPORTED;
    goto cleanup;
  }
  if(EVP_PKEY_fromdata_init(context) <= 0) {
    goto cleanup;
  }
  params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)public_key, public_key_len);
  if(private_key != NULL) {
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)private_key, private_key_len);
    params[2] = OSSL_PARAM_construct_end();
    selection = EVP_PKEY_KEYPAIR;
  } else {
    params[1] = OSSL_PARAM_construct_end();
    selection = EVP_PKEY_PUBLIC_KEY;
  }
  if(EVP_PKEY_fromdata(context, &key, selection, params) <= 0) {
    goto cleanup;
  }
  validation_context = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
  if(validation_context == NULL) {
    result = TEXTRUNSQL_PQ_ERROR_ALLOCATION;
    goto cleanup;
  }
  if((private_key != NULL && EVP_PKEY_pairwise_check(validation_context) <= 0) || (private_key == NULL && EVP_PKEY_public_check(validation_context) <= 0)) {
    goto cleanup;
  }
  *key_out = key;
  key = NULL;
  result = TEXTRUNSQL_PQ_OK;

cleanup:
  EVP_PKEY_CTX_free(validation_context);
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(context);
  return result == TEXTRUNSQL_PQ_OK ? result : textrunsql_provider_failure(result);
}

int textrunsql_provider_key_export_public(EVP_PKEY *key, unsigned char public_key[TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES]) {
  size_t length = TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES;

  if(key == NULL || public_key == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  ERR_clear_error();
  if(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, public_key, length, &length) <= 0 || length != TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES) {
    OPENSSL_cleanse(public_key, TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES);
    return textrunsql_provider_failure(TEXTRUNSQL_PQ_ERROR_CRYPTO);
  }
  return TEXTRUNSQL_PQ_OK;
}

int textrunsql_provider_key_export_private(EVP_PKEY *key, unsigned char private_key[TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES]) {
  size_t length = TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES;

  if(key == NULL || private_key == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  ERR_clear_error();
  if(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY, private_key, length, &length) <= 0 || length != TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES) {
    OPENSSL_cleanse(private_key, TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES);
    return textrunsql_provider_failure(TEXTRUNSQL_PQ_ERROR_CRYPTO);
  }
  return TEXTRUNSQL_PQ_OK;
}

int textrunsql_provider_encapsulate(EVP_PKEY *key, const unsigned char *test_ikme, size_t test_ikme_len, unsigned char ciphertext[TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES], unsigned char shared_secret[TEXTRUNSQL_PQ_SHARED_SECRET_BYTES]) {
  EVP_PKEY_CTX *context = NULL;
  OSSL_PARAM params[2];
  const OSSL_PARAM *init_params = NULL;
  size_t ciphertext_len = TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES;
  size_t shared_secret_len = TEXTRUNSQL_PQ_SHARED_SECRET_BYTES;
  int result = TEXTRUNSQL_PQ_ERROR_CRYPTO;

  if(key == NULL || ciphertext == NULL || shared_secret == NULL || (test_ikme == NULL && test_ikme_len != 0) || (test_ikme != NULL && test_ikme_len != 32)) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
#ifdef TEXTRUNSQL_TESTING
  if(textrunsql_test_fail_consume(TEXTRUNSQL_TEST_FAIL_KEM)) {
    OPENSSL_cleanse(ciphertext, TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES);
    OPENSSL_cleanse(shared_secret, TEXTRUNSQL_PQ_SHARED_SECRET_BYTES);
    return TEXTRUNSQL_PQ_ERROR_CRYPTO;
  }
#endif
  ERR_clear_error();
  context = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
  if(context == NULL) {
    goto cleanup;
  }
  if(test_ikme != NULL) {
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, (void *)test_ikme, test_ikme_len);
    params[1] = OSSL_PARAM_construct_end();
    init_params = params;
  }
  if(EVP_PKEY_encapsulate_init(context, init_params) <= 0) {
    goto cleanup;
  }
  if(EVP_PKEY_encapsulate(context, ciphertext, &ciphertext_len, shared_secret, &shared_secret_len) <= 0) {
    goto cleanup;
  }
  if(ciphertext_len != TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES || shared_secret_len != TEXTRUNSQL_PQ_SHARED_SECRET_BYTES) {
    goto cleanup;
  }
  result = TEXTRUNSQL_PQ_OK;

cleanup:
  EVP_PKEY_CTX_free(context);
  if(result != TEXTRUNSQL_PQ_OK) {
    OPENSSL_cleanse(ciphertext, TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES);
    OPENSSL_cleanse(shared_secret, TEXTRUNSQL_PQ_SHARED_SECRET_BYTES);
    return textrunsql_provider_failure(result);
  }
  return result;
}

int textrunsql_provider_decapsulate(EVP_PKEY *key, const unsigned char ciphertext[TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES], unsigned char shared_secret[TEXTRUNSQL_PQ_SHARED_SECRET_BYTES]) {
  EVP_PKEY_CTX *context = NULL;
  size_t shared_secret_len = TEXTRUNSQL_PQ_SHARED_SECRET_BYTES;
  int result = TEXTRUNSQL_PQ_ERROR_CRYPTO;

  if(key == NULL || ciphertext == NULL || shared_secret == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
#ifdef TEXTRUNSQL_TESTING
  if(textrunsql_test_fail_consume(TEXTRUNSQL_TEST_FAIL_KEM)) {
    OPENSSL_cleanse(shared_secret, TEXTRUNSQL_PQ_SHARED_SECRET_BYTES);
    return TEXTRUNSQL_PQ_ERROR_CRYPTO;
  }
#endif
  ERR_clear_error();
  context = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
  if(context == NULL) {
    goto cleanup;
  }
  if(EVP_PKEY_decapsulate_init(context, NULL) <= 0) {
    goto cleanup;
  }
  if(EVP_PKEY_decapsulate(context, shared_secret, &shared_secret_len, ciphertext, TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES) <= 0 || shared_secret_len != TEXTRUNSQL_PQ_SHARED_SECRET_BYTES) {
    goto cleanup;
  }
  result = TEXTRUNSQL_PQ_OK;

cleanup:
  EVP_PKEY_CTX_free(context);
  if(result != TEXTRUNSQL_PQ_OK) {
    OPENSSL_cleanse(shared_secret, TEXTRUNSQL_PQ_SHARED_SECRET_BYTES);
    return textrunsql_provider_failure(result);
  }
  return result;
}

int textrunsql_provider_sha256(const unsigned char *input, size_t input_len, unsigned char output[32]) {
  EVP_MD *digest = NULL;
  unsigned int output_len = 0;
  int result = TEXTRUNSQL_PQ_ERROR_CRYPTO;

  if((input == NULL && input_len != 0) || output == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  ERR_clear_error();
  digest = EVP_MD_fetch(NULL, "SHA256", NULL);
  if(digest == NULL) {
    return textrunsql_provider_failure(TEXTRUNSQL_PQ_ERROR_UNSUPPORTED);
  }
  if(EVP_Digest(input, input_len, output, &output_len, digest, NULL) > 0 && output_len == 32) {
    result = TEXTRUNSQL_PQ_OK;
  }
  EVP_MD_free(digest);
  if(result != TEXTRUNSQL_PQ_OK) {
    OPENSSL_cleanse(output, 32);
    return textrunsql_provider_failure(result);
  }
  return result;
}

int textrunsql_provider_hkdf(const unsigned char shared_secret[TEXTRUNSQL_PQ_SHARED_SECRET_BYTES], const unsigned char salt[32], unsigned char output[32]) {
  static const char info[] = "TextrunSQL/PQEnvelope/v1/ML-KEM-768/HKDF-SHA-256/AES-256-GCM";
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *context = NULL;
  OSSL_PARAM params[5];
  int result = TEXTRUNSQL_PQ_ERROR_CRYPTO;

  if(shared_secret == NULL || salt == NULL || output == NULL) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
#ifdef TEXTRUNSQL_TESTING
  if(textrunsql_test_fail_consume(TEXTRUNSQL_TEST_FAIL_HKDF)) {
    OPENSSL_cleanse(output, 32);
    return TEXTRUNSQL_PQ_ERROR_CRYPTO;
  }
#endif
  ERR_clear_error();
  kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  if(kdf == NULL) {
    result = TEXTRUNSQL_PQ_ERROR_UNSUPPORTED;
    goto cleanup;
  }
  context = EVP_KDF_CTX_new(kdf);
  if(context == NULL) {
    result = TEXTRUNSQL_PQ_ERROR_ALLOCATION;
    goto cleanup;
  }
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)shared_secret, TEXTRUNSQL_PQ_SHARED_SECRET_BYTES);
  params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, 32);
  params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, sizeof(info) - 1);
  params[4] = OSSL_PARAM_construct_end();
  if(EVP_KDF_derive(context, output, 32, params) <= 0) {
    goto cleanup;
  }
  result = TEXTRUNSQL_PQ_OK;

cleanup:
  EVP_KDF_CTX_free(context);
  EVP_KDF_free(kdf);
  if(result != TEXTRUNSQL_PQ_OK) {
    OPENSSL_cleanse(output, 32);
    return textrunsql_provider_failure(result);
  }
  return result;
}

int textrunsql_provider_random(unsigned char *output, size_t output_len) {
  if(output == NULL || output_len == 0) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
#ifdef TEXTRUNSQL_TESTING
  if(textrunsql_test_fail_consume(TEXTRUNSQL_TEST_FAIL_RANDOM)) {
    OPENSSL_cleanse(output, output_len);
    return TEXTRUNSQL_PQ_ERROR_CRYPTO;
  }
#endif
  ERR_clear_error();
  if(RAND_bytes_ex(NULL, output, output_len, 0) <= 0) {
    OPENSSL_cleanse(output, output_len);
    return textrunsql_provider_failure(TEXTRUNSQL_PQ_ERROR_CRYPTO);
  }
  return TEXTRUNSQL_PQ_OK;
}

int textrunsql_provider_aead_encrypt(const unsigned char key[32], const unsigned char nonce[TEXTRUNSQL_PQ_NONCE_BYTES], const unsigned char *aad, size_t aad_len, const unsigned char plaintext[32], unsigned char ciphertext[32], unsigned char tag[TEXTRUNSQL_PQ_TAG_BYTES]) {
  EVP_CIPHER *cipher = NULL;
  EVP_CIPHER_CTX *context = NULL;
  int length = 0;
  int total = 0;
  int result = TEXTRUNSQL_PQ_ERROR_CRYPTO;

  if(key == NULL || nonce == NULL || (aad == NULL && aad_len != 0) || plaintext == NULL || ciphertext == NULL || tag == NULL || aad_len > INT_MAX) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
#ifdef TEXTRUNSQL_TESTING
  if(textrunsql_test_fail_consume(TEXTRUNSQL_TEST_FAIL_AEAD)) {
    OPENSSL_cleanse(ciphertext, 32);
    OPENSSL_cleanse(tag, TEXTRUNSQL_PQ_TAG_BYTES);
    return TEXTRUNSQL_PQ_ERROR_CRYPTO;
  }
#endif
  ERR_clear_error();
  cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
  context = EVP_CIPHER_CTX_new();
  if(cipher == NULL) {
    result = TEXTRUNSQL_PQ_ERROR_UNSUPPORTED;
    goto cleanup;
  }
  if(context == NULL) {
    result = TEXTRUNSQL_PQ_ERROR_ALLOCATION;
    goto cleanup;
  }
  if(EVP_EncryptInit_ex2(context, cipher, key, nonce, NULL) <= 0) {
    goto cleanup;
  }
  if(aad_len != 0 && EVP_EncryptUpdate(context, NULL, &length, aad, (int)aad_len) <= 0) {
    goto cleanup;
  }
  if(EVP_EncryptUpdate(context, ciphertext, &length, plaintext, 32) <= 0) {
    goto cleanup;
  }
  total = length;
  if(EVP_EncryptFinal_ex(context, ciphertext + total, &length) <= 0) {
    goto cleanup;
  }
  total += length;
  if(total != 32 || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, TEXTRUNSQL_PQ_TAG_BYTES, tag) <= 0) {
    goto cleanup;
  }
  result = TEXTRUNSQL_PQ_OK;

cleanup:
  EVP_CIPHER_CTX_free(context);
  EVP_CIPHER_free(cipher);
  if(result != TEXTRUNSQL_PQ_OK) {
    OPENSSL_cleanse(ciphertext, 32);
    OPENSSL_cleanse(tag, TEXTRUNSQL_PQ_TAG_BYTES);
    return textrunsql_provider_failure(result);
  }
  return result;
}

int textrunsql_provider_aead_decrypt(const unsigned char key[32], const unsigned char nonce[TEXTRUNSQL_PQ_NONCE_BYTES], const unsigned char *aad, size_t aad_len, const unsigned char ciphertext[32], const unsigned char tag[TEXTRUNSQL_PQ_TAG_BYTES], unsigned char plaintext[32]) {
  EVP_CIPHER *cipher = NULL;
  EVP_CIPHER_CTX *context = NULL;
  int length = 0;
  int total = 0;
  int result = TEXTRUNSQL_PQ_ERROR_AUTHENTICATION;

  if(key == NULL || nonce == NULL || (aad == NULL && aad_len != 0) || ciphertext == NULL || tag == NULL || plaintext == NULL || aad_len > INT_MAX) {
    return TEXTRUNSQL_PQ_ERROR_MISUSE;
  }
  ERR_clear_error();
  cipher = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
  context = EVP_CIPHER_CTX_new();
  if(cipher == NULL) {
    result = TEXTRUNSQL_PQ_ERROR_UNSUPPORTED;
    goto cleanup;
  }
  if(context == NULL) {
    result = TEXTRUNSQL_PQ_ERROR_ALLOCATION;
    goto cleanup;
  }
  if(EVP_DecryptInit_ex2(context, cipher, key, nonce, NULL) <= 0) {
    result = TEXTRUNSQL_PQ_ERROR_CRYPTO;
    goto cleanup;
  }
  if(aad_len != 0 && EVP_DecryptUpdate(context, NULL, &length, aad, (int)aad_len) <= 0) {
    result = TEXTRUNSQL_PQ_ERROR_CRYPTO;
    goto cleanup;
  }
  if(EVP_DecryptUpdate(context, plaintext, &length, ciphertext, 32) <= 0) {
    result = TEXTRUNSQL_PQ_ERROR_CRYPTO;
    goto cleanup;
  }
  total = length;
  if(EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, TEXTRUNSQL_PQ_TAG_BYTES, (void *)tag) <= 0) {
    result = TEXTRUNSQL_PQ_ERROR_CRYPTO;
    goto cleanup;
  }
  if(EVP_DecryptFinal_ex(context, plaintext + total, &length) <= 0) {
    result = TEXTRUNSQL_PQ_ERROR_AUTHENTICATION;
    goto cleanup;
  }
  total += length;
  if(total != 32) {
    result = TEXTRUNSQL_PQ_ERROR_CRYPTO;
    goto cleanup;
  }
  result = TEXTRUNSQL_PQ_OK;

cleanup:
  EVP_CIPHER_CTX_free(context);
  EVP_CIPHER_free(cipher);
  if(result != TEXTRUNSQL_PQ_OK) {
    OPENSSL_cleanse(plaintext, 32);
    return textrunsql_provider_failure(result);
  }
  return result;
}
