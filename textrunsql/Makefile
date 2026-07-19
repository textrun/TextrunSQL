CC ?= cc
AR ?= ar
RANLIB ?= ranlib
FUZZ_CC ?= $(shell command -v brew >/dev/null 2>&1 && test -x "$$(brew --prefix llvm 2>/dev/null)/bin/clang" && echo "$$(brew --prefix llvm)/bin/clang" || echo "$(CC)")

OPENSSL_PREFIX ?= $(shell command -v brew >/dev/null 2>&1 && brew --prefix openssl@3 2>/dev/null)
OPENSSL_CFLAGS ?= $(if $(OPENSSL_PREFIX),-I$(OPENSSL_PREFIX)/include)
OPENSSL_LIBS ?= $(if $(OPENSSL_PREFIX),-L$(OPENSSL_PREFIX)/lib) -lcrypto
SQLCIPHER_LIB ?= ../libsqlite3.a

CPPFLAGS += -DSQLITE_HAS_CODEC -Iinclude -Isrc -I../ $(OPENSSL_CFLAGS)
BASE_CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -Werror
CFLAGS ?= -O2
BUILD_DIR ?= build

SOURCES = src/envelope.c src/provider_openssl.c src/keyspec.c
HEADERS = include/textrunsql_pq.h src/internal.h
OBJECTS = $(SOURCES:src/%.c=$(BUILD_DIR)/%.o)
TEST_OBJECTS = $(BUILD_DIR)/test/envelope.o $(BUILD_DIR)/test/provider_openssl.o
FUZZ_OBJECTS = $(BUILD_DIR)/fuzz/envelope.o $(BUILD_DIR)/fuzz/provider_openssl.o
FUZZ_SEED = $(BUILD_DIR)/fuzz-corpus/envelope-v1
LIBRARY = $(BUILD_DIR)/libtextrunsql_pq.a

.PHONY: all check test test-sqlcipher test-tcl asan fuzz-smoke clean

all: $(LIBRARY)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/test:
	mkdir -p $(BUILD_DIR)/test

$(BUILD_DIR)/fuzz:
	mkdir -p $(BUILD_DIR)/fuzz

$(BUILD_DIR)/fuzz-corpus:
	mkdir -p $(BUILD_DIR)/fuzz-corpus

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/test/%.o: src/%.c | $(BUILD_DIR)/test
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(CFLAGS) -DTEXTRUNSQL_TESTING -c $< -o $@

$(BUILD_DIR)/fuzz/%.o: src/%.c | $(BUILD_DIR)/fuzz
	$(FUZZ_CC) $(CPPFLAGS) $(BASE_CFLAGS) -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -DTEXTRUNSQL_TESTING -c $< -o $@

$(OBJECTS) $(TEST_OBJECTS) $(FUZZ_OBJECTS): $(HEADERS)

$(LIBRARY): $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)
	$(RANLIB) $@

$(BUILD_DIR)/test_envelope: test/test_envelope.c $(TEST_OBJECTS)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(CFLAGS) -DTEXTRUNSQL_TESTING $^ $(OPENSSL_LIBS) -o $@

$(BUILD_DIR)/test_acvp: test/test_acvp.c $(TEST_OBJECTS)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(CFLAGS) -DTEXTRUNSQL_TESTING $^ $(OPENSSL_LIBS) -o $@

test: $(BUILD_DIR)/test_envelope $(BUILD_DIR)/test_acvp
	$(BUILD_DIR)/test_envelope
	$(BUILD_DIR)/test_acvp

$(BUILD_DIR)/test_keyspec: test/test_keyspec.c $(LIBRARY) $(SQLCIPHER_LIB)
	$(CC) $(CPPFLAGS) $(BASE_CFLAGS) $(CFLAGS) $< $(LIBRARY) $(SQLCIPHER_LIB) $(OPENSSL_LIBS) -lz -lm -ldl -lpthread -o $@

test-sqlcipher: $(BUILD_DIR)/test_keyspec
	$(BUILD_DIR)/test_keyspec

test-tcl:
	cd .. && ./testfixture test/textrunsql.test

check: test test-sqlcipher test-tcl

asan:
	$(MAKE) BUILD_DIR=build/asan CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined" test test-sqlcipher

$(BUILD_DIR)/fuzz_envelope: test/fuzz_envelope.c $(FUZZ_OBJECTS)
	$(FUZZ_CC) $(CPPFLAGS) $(BASE_CFLAGS) -O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -DTEXTRUNSQL_TESTING $^ $(OPENSSL_LIBS) -o $@

$(FUZZ_SEED): vectors/envelope-v1.hex | $(BUILD_DIR)/fuzz-corpus
	xxd -r -p $< $@

fuzz-smoke: $(BUILD_DIR)/fuzz_envelope $(FUZZ_SEED)
	$(BUILD_DIR)/fuzz_envelope $(BUILD_DIR)/fuzz-corpus -dict=test/envelope.dict -runs=5000

clean:
	@echo "Move $(BUILD_DIR) to Trash manually; this Makefile does not delete files."
