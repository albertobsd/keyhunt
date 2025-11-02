ARCH ?= $(shell uname -m)

ifeq ($(ARCH),aarch64)
ARCH_FLAGS = -march=armv8-a -mtune=native
else
ARCH_FLAGS = -march=native -mtune=native
endif

COMMON_OPT = -O3 -ffast-math -flto -ftree-vectorize
BASE_CXXFLAGS = $(COMMON_OPT) $(ARCH_FLAGS) -Wall -Wextra -Wno-deprecated-copy
BASE_CFLAGS = $(COMMON_OPT) $(ARCH_FLAGS) -Wall -Wextra

CXX ?= g++
CC = gcc

LIBS = -lm -lpthread
LEGACY_LIBS = -lm -lpthread -lcrypto -lgmp

default:
	$(CXX) $(BASE_CXXFLAGS) -c oldbloom/bloom.cpp -o oldbloom.o
	$(CXX) $(BASE_CXXFLAGS) -c bloom/bloom.cpp -o bloom.o
	$(CC) $(BASE_CFLAGS) -Wno-unused-parameter -c base58/base58.c -o base58.o
	$(CC) $(BASE_CFLAGS) -c rmd160/rmd160.c -o rmd160.o
	$(CXX) $(BASE_CXXFLAGS) -c sha3/sha3.c -o sha3.o
	$(CXX) $(BASE_CXXFLAGS) -c sha3/keccak.c -o keccak.o
	$(CC) $(BASE_CFLAGS) -c xxhash/xxhash.c -o xxhash.o
	$(CXX) $(BASE_CXXFLAGS) -c util.c -o util.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/Int.cpp -o Int.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/Point.cpp -o Point.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/SECP256K1.cpp -o SECP256K1.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/IntMod.cpp -o IntMod.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/Random.cpp -o Random.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/IntGroup.cpp -o IntGroup.o
	$(CXX) $(BASE_CXXFLAGS) -c hash/ripemd160.cpp -o hash/ripemd160.o
	$(CXX) $(BASE_CXXFLAGS) -c hash/sha256.cpp -o hash/sha256.o
	$(CXX) $(BASE_CXXFLAGS) -c hash/ripemd160_sse.cpp -o hash/ripemd160_sse.o
	$(CXX) $(BASE_CXXFLAGS) -c hash/sha256_sse.cpp -o hash/sha256_sse.o
	$(CXX) $(BASE_CXXFLAGS) -o keyhunt keyhunt.cpp base58.o rmd160.o hash/ripemd160.o hash/ripemd160_sse.o hash/sha256.o hash/sha256_sse.o bloom.o oldbloom.o xxhash.o util.o Int.o Point.o SECP256K1.o IntMod.o Random.o IntGroup.o sha3.o keccak.o $(LIBS)
	rm -f *.o

legacy:
	$(CXX) $(BASE_CXXFLAGS) -c oldbloom/bloom.cpp -o oldbloom.o
	$(CXX) $(BASE_CXXFLAGS) -c bloom/bloom.cpp -o bloom.o
	$(CC) $(BASE_CFLAGS) -Wno-unused-result -c base58/base58.c -o base58.o
	$(CC) $(BASE_CFLAGS) -c xxhash/xxhash.c -o xxhash.o
	$(CXX) $(BASE_CXXFLAGS) -c util.c -o util.o
	$(CXX) $(BASE_CXXFLAGS) -c sha3/sha3.c -o sha3.o
	$(CXX) $(BASE_CXXFLAGS) -c sha3/keccak.c -o keccak.o
	$(CXX) $(BASE_CXXFLAGS) -c hashing.c -o hashing.o
	$(CXX) $(BASE_CXXFLAGS) -c gmp256k1/Int.cpp -o Int.o
	$(CXX) $(BASE_CXXFLAGS) -c gmp256k1/Point.cpp -o Point.o
	$(CXX) $(BASE_CXXFLAGS) -c gmp256k1/GMP256K1.cpp -o GMP256K1.o
	$(CXX) $(BASE_CXXFLAGS) -c gmp256k1/IntMod.cpp -o IntMod.o
	$(CXX) $(BASE_CXXFLAGS) -c gmp256k1/Random.cpp -o Random.o
	$(CXX) $(BASE_CXXFLAGS) -c gmp256k1/IntGroup.cpp -o IntGroup.o
	$(CXX) $(BASE_CXXFLAGS) -o keyhunt keyhunt_legacy.cpp base58.o bloom.o oldbloom.o xxhash.o util.o Int.o Point.o GMP256K1.o IntMod.o IntGroup.o Random.o hashing.o sha3.o keccak.o $(LEGACY_LIBS)
	rm -f *.o

bsgsd:
	$(CXX) $(BASE_CXXFLAGS) -c oldbloom/bloom.cpp -o oldbloom.o
	$(CXX) $(BASE_CXXFLAGS) -c bloom/bloom.cpp -o bloom.o
	$(CC) $(BASE_CFLAGS) -Wno-unused-parameter -c base58/base58.c -o base58.o
	$(CC) $(BASE_CFLAGS) -c rmd160/rmd160.c -o rmd160.o
	$(CXX) $(BASE_CXXFLAGS) -c sha3/sha3.c -o sha3.o
	$(CXX) $(BASE_CXXFLAGS) -c sha3/keccak.c -o keccak.o
	$(CC) $(BASE_CFLAGS) -c xxhash/xxhash.c -o xxhash.o
	$(CXX) $(BASE_CXXFLAGS) -c util.c -o util.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/Int.cpp -o Int.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/Point.cpp -o Point.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/SECP256K1.cpp -o SECP256K1.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/IntMod.cpp -o IntMod.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/Random.cpp -o Random.o
	$(CXX) $(BASE_CXXFLAGS) -c secp256k1/IntGroup.cpp -o IntGroup.o
	$(CXX) $(BASE_CXXFLAGS) -c hash/ripemd160.cpp -o hash/ripemd160.o
	$(CXX) $(BASE_CXXFLAGS) -c hash/sha256.cpp -o hash/sha256.o
	$(CXX) $(BASE_CXXFLAGS) -c hash/ripemd160_sse.cpp -o hash/ripemd160_sse.o
	$(CXX) $(BASE_CXXFLAGS) -c hash/sha256_sse.cpp -o hash/sha256_sse.o
	$(CXX) $(BASE_CXXFLAGS) -o bsgsd bsgsd.cpp base58.o rmd160.o hash/ripemd160.o hash/ripemd160_sse.o hash/sha256.o hash/sha256_sse.o bloom.o oldbloom.o xxhash.o util.o Int.o Point.o SECP256K1.o IntMod.o Random.o IntGroup.o sha3.o keccak.o $(LIBS)
	rm -f *.o

clean:
	rm -f keyhunt bsgsd
