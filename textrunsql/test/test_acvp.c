#include "internal.h"

#include <openssl/crypto.h>

#include <stdio.h>
#include <string.h>

#define CHECK(expression) do { if(!(expression)) { fprintf(stderr, "check failed at %s:%d: %s\n", __FILE__, __LINE__, #expression); goto cleanup; } } while(0)

static int hex_value(int character) {
  if(character >= '0' && character <= '9') {
    return character - '0';
  }
  if(character >= 'a' && character <= 'f') {
    return character - 'a' + 10;
  }
  if(character >= 'A' && character <= 'F') {
    return character - 'A' + 10;
  }
  return -1;
}

static int load_field(FILE *file, const char *name, unsigned char *output, size_t output_len) {
  char line[6000];
  size_t name_len = strlen(name);
  size_t index;

  rewind(file);
  while(fgets(line, sizeof(line), file) != NULL) {
    size_t line_len = strcspn(line, "\r\n");
    if(strncmp(line, name, name_len) != 0 || line[name_len] != '=') {
      continue;
    }
    if(line_len != name_len + 1 + (output_len * 2)) {
      return 0;
    }
    for(index = 0; index < output_len; index++) {
      int high = hex_value(line[name_len + 1 + (index * 2)]);
      int low = hex_value(line[name_len + 2 + (index * 2)]);
      if(high < 0 || low < 0) {
        return 0;
      }
      output[index] = (unsigned char)((high << 4) | low);
    }
    return 1;
  }
  return 0;
}

static int load_hex_file(const char *path, unsigned char *output, size_t output_len) {
  FILE *file = NULL;
  size_t index;
  int result = 0;

  file = fopen(path, "rb");
  if(file == NULL) {
    return 0;
  }
  for(index = 0; index < output_len; index++) {
    int high = fgetc(file);
    int low = fgetc(file);
    high = hex_value(high);
    low = hex_value(low);
    if(high < 0 || low < 0) {
      goto cleanup;
    }
    output[index] = (unsigned char)((high << 4) | low);
  }
  if(fgetc(file) != '\n' || fgetc(file) != EOF) {
    goto cleanup;
  }
  result = 1;

cleanup:
  fclose(file);
  return result;
}

static void print_hex(const unsigned char *input, size_t input_len) {
  static const char hex[] = "0123456789abcdef";
  size_t index;

  for(index = 0; index < input_len; index++) {
    putchar(hex[input[index] >> 4]);
    putchar(hex[input[index] & 0x0f]);
  }
  putchar('\n');
}

int main(int argc, char **argv) {
  static const unsigned char context[] = "textrunsql/vector/customer-0001/database-0001";
  FILE *vectors = NULL;
  textrunsql_pq_key *keygen_key = NULL;
  textrunsql_pq_key *encap_key = NULL;
  unsigned char keygen_seed[64];
  unsigned char keygen_public[TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES];
  unsigned char keygen_private[TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES];
  unsigned char actual_public[TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES];
  unsigned char actual_private[TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES];
  unsigned char encap_public[TEXTRUNSQL_PQ_PUBLIC_KEY_BYTES];
  unsigned char encap_private[TEXTRUNSQL_PQ_PRIVATE_KEY_BYTES];
  unsigned char encap_ikme[32];
  unsigned char expected_ciphertext[TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES];
  unsigned char expected_shared_secret[TEXTRUNSQL_PQ_SHARED_SECRET_BYTES];
  unsigned char actual_ciphertext[TEXTRUNSQL_PQ_KEM_CIPHERTEXT_BYTES];
  unsigned char actual_shared_secret[TEXTRUNSQL_PQ_SHARED_SECRET_BYTES];
  unsigned char dek[TEXTRUNSQL_PQ_DEK_BYTES];
  unsigned char opened_dek[TEXTRUNSQL_PQ_DEK_BYTES];
  unsigned char nonce[TEXTRUNSQL_PQ_NONCE_BYTES];
  unsigned char envelope[TEXTRUNSQL_PQ_ENVELOPE_BYTES];
  unsigned char expected_envelope[TEXTRUNSQL_PQ_ENVELOPE_BYTES];
  size_t length;
  size_t index;
  int print_mode = argc == 2 && strcmp(argv[1], "--print-envelope") == 0;
  int result = 1;

  if(argc > 2 || (argc == 2 && !print_mode)) {
    fprintf(stderr, "usage: %s [--print-envelope]\n", argv[0]);
    return 2;
  }
  for(index = 0; index < sizeof(dek); index++) {
    dek[index] = (unsigned char)(0xa0U + index);
  }
  for(index = 0; index < sizeof(nonce); index++) {
    nonce[index] = (unsigned char)index;
  }
  vectors = fopen("vectors/mlkem768-acvp.txt", "rb");
  CHECK(vectors != NULL);
  CHECK(load_field(vectors, "keygen_seed", keygen_seed, sizeof(keygen_seed)));
  CHECK(load_field(vectors, "keygen_public", keygen_public, sizeof(keygen_public)));
  CHECK(load_field(vectors, "keygen_private", keygen_private, sizeof(keygen_private)));
  CHECK(load_field(vectors, "encap_public", encap_public, sizeof(encap_public)));
  CHECK(load_field(vectors, "encap_private", encap_private, sizeof(encap_private)));
  CHECK(load_field(vectors, "encap_ikme", encap_ikme, sizeof(encap_ikme)));
  CHECK(load_field(vectors, "encap_ciphertext", expected_ciphertext, sizeof(expected_ciphertext)));
  CHECK(load_field(vectors, "encap_shared_secret", expected_shared_secret, sizeof(expected_shared_secret)));

  CHECK(textrunsql_pq_test_key_from_seed(keygen_seed, &keygen_key) == TEXTRUNSQL_PQ_OK);
  length = sizeof(actual_public);
  CHECK(textrunsql_pq_key_export_public(keygen_key, actual_public, &length) == TEXTRUNSQL_PQ_OK);
  CHECK(length == sizeof(actual_public));
  CHECK(CRYPTO_memcmp(actual_public, keygen_public, sizeof(actual_public)) == 0);
  length = sizeof(actual_private);
  CHECK(textrunsql_pq_key_export_private(keygen_key, actual_private, &length) == TEXTRUNSQL_PQ_OK);
  CHECK(length == sizeof(actual_private));
  CHECK(CRYPTO_memcmp(actual_private, keygen_private, sizeof(actual_private)) == 0);

  CHECK(textrunsql_pq_key_import_private(encap_public, sizeof(encap_public), encap_private, sizeof(encap_private), &encap_key) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_provider_encapsulate(encap_key->pkey, encap_ikme, sizeof(encap_ikme), actual_ciphertext, actual_shared_secret) == TEXTRUNSQL_PQ_OK);
  CHECK(CRYPTO_memcmp(actual_ciphertext, expected_ciphertext, sizeof(actual_ciphertext)) == 0);
  CHECK(CRYPTO_memcmp(actual_shared_secret, expected_shared_secret, sizeof(actual_shared_secret)) == 0);
  OPENSSL_cleanse(actual_shared_secret, sizeof(actual_shared_secret));
  CHECK(textrunsql_provider_decapsulate(encap_key->pkey, expected_ciphertext, actual_shared_secret) == TEXTRUNSQL_PQ_OK);
  CHECK(CRYPTO_memcmp(actual_shared_secret, expected_shared_secret, sizeof(actual_shared_secret)) == 0);

  CHECK(textrunsql_pq_test_seal_dek(keygen_key, context, sizeof(context) - 1, dek, encap_ikme, nonce, envelope) == TEXTRUNSQL_PQ_OK);
  CHECK(textrunsql_pq_open_dek(keygen_key, context, sizeof(context) - 1, envelope, sizeof(envelope), opened_dek) == TEXTRUNSQL_PQ_OK);
  CHECK(CRYPTO_memcmp(opened_dek, dek, sizeof(dek)) == 0);
  if(print_mode) {
    print_hex(envelope, sizeof(envelope));
  } else {
    CHECK(load_hex_file("vectors/envelope-v1.hex", expected_envelope, sizeof(expected_envelope)));
    CHECK(CRYPTO_memcmp(envelope, expected_envelope, sizeof(envelope)) == 0);
  }
  result = 0;

cleanup:
  if(vectors != NULL) {
    fclose(vectors);
  }
  OPENSSL_cleanse(keygen_seed, sizeof(keygen_seed));
  OPENSSL_cleanse(keygen_private, sizeof(keygen_private));
  OPENSSL_cleanse(actual_private, sizeof(actual_private));
  OPENSSL_cleanse(encap_private, sizeof(encap_private));
  OPENSSL_cleanse(encap_ikme, sizeof(encap_ikme));
  OPENSSL_cleanse(expected_shared_secret, sizeof(expected_shared_secret));
  OPENSSL_cleanse(actual_shared_secret, sizeof(actual_shared_secret));
  OPENSSL_cleanse(dek, sizeof(dek));
  OPENSSL_cleanse(opened_dek, sizeof(opened_dek));
  OPENSSL_cleanse(envelope, sizeof(envelope));
  OPENSSL_cleanse(expected_envelope, sizeof(expected_envelope));
  textrunsql_pq_key_free(encap_key);
  textrunsql_pq_key_free(keygen_key);
  if(result == 0 && !print_mode) {
    puts("test_acvp: ok");
  }
  return result;
}
