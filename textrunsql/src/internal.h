#ifndef TEXTRUNSQL_INTERNAL_H
#define TEXTRUNSQL_INTERNAL_H

#include "textrunsql_pq.h"

#include <openssl/evp.h>

#define TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES 1088U
#define TEXTRUNSQL_PQ_SHARED_SECRET_BYTES 32U
#define TEXTRUNSQL_PQ_NONCE_BYTES 12U
#define TEXTRUNSQL_PQ_TAG_BYTES 16U

struct textrunsql_pq_key {
  EVP_PKEY *pkey;
  unsigned char public_key[TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES];
  int has_private;
};

int textrunsql_provider_key_generate(const unsigned char *seed, size_t seed_len, EVP_PKEY **key_out);
int textrunsql_provider_key_import(const unsigned char *public_key, size_t public_key_len, const unsigned char *private_key, size_t private_key_len, EVP_PKEY **key_out);
int textrunsql_provider_key_export_public(EVP_PKEY *key, unsigned char public_key[TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES]);
int textrunsql_provider_key_export_private(EVP_PKEY *key, unsigned char private_key[TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES]);
int textrunsql_provider_encapsulate(EVP_PKEY *key, const unsigned char *test_ikme, size_t test_ikme_len, unsigned char ciphertext[TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES], unsigned char shared_secret[TEXTRUNSQL_PQ_SHARED_SECRET_BYTES]);
int textrunsql_provider_decapsulate(EVP_PKEY *key, const unsigned char ciphertext[TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES], unsigned char shared_secret[TEXTRUNSQL_PQ_SHARED_SECRET_BYTES]);
int textrunsql_provider_sha256(const unsigned char *input, size_t input_len, unsigned char output[32]);
int textrunsql_provider_hkdf(const unsigned char shared_secret[TEXTRUNSQL_PQ_SHARED_SECRET_BYTES], const unsigned char salt[32], unsigned char output[32]);
int textrunsql_provider_random(unsigned char *output, size_t output_len);
int textrunsql_provider_aead_encrypt(const unsigned char key[32], const unsigned char nonce[TEXTRUNSQL_PQ_NONCE_BYTES], const unsigned char *aad, size_t aad_len, const unsigned char plaintext[32], unsigned char ciphertext[32], unsigned char tag[TEXTRUNSQL_PQ_TAG_BYTES]);
int textrunsql_provider_aead_decrypt(const unsigned char key[32], const unsigned char nonce[TEXTRUNSQL_PQ_NONCE_BYTES], const unsigned char *aad, size_t aad_len, const unsigned char ciphertext[32], const unsigned char tag[TEXTRUNSQL_PQ_TAG_BYTES], unsigned char plaintext[32]);

#ifdef TEXTRUNSQL_TESTING
typedef enum textrunsql_test_failpoint {
  TEXTRUNSQL_TEST_FAIL_NONE = 0,
  TEXTRUNSQL_TEST_FAIL_KEY_ALLOCATION = 1,
  TEXTRUNSQL_TEST_FAIL_KEM = 2,
  TEXTRUNSQL_TEST_FAIL_RANDOM = 3,
  TEXTRUNSQL_TEST_FAIL_HKDF = 4,
  TEXTRUNSQL_TEST_FAIL_AEAD = 5
} textrunsql_test_failpoint;

void textrunsql_test_fail_next(textrunsql_test_failpoint failpoint);
int textrunsql_test_fail_consume(textrunsql_test_failpoint failpoint);
int textrunsql_pq_test_key_from_seed(const uint8_t seed[64], textrunsql_pq_key **key_out);
int textrunsql_pq_test_seal_dek(const textrunsql_pq_key *recipient, const uint8_t *context, size_t context_len, const uint8_t dek[TEXTRUNSQL_PQ_DEK_BYTES], const uint8_t ikme[32], const uint8_t nonce[TEXTRUNSQL_PQ_NONCE_BYTES], uint8_t envelope_out[TEXTRUNSQL_PQ_ENVELOPE_BYTES]);
#endif

#endif
