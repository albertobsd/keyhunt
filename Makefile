CXX ?= g++
CC ?= gcc

COMMON_OPT = -O3 -ffast-math -ftree-vectorize

CXXFLAGS ?=
CFLAGS ?=

CXXFLAGS += $(COMMON_OPT) -Wall -Wextra -Wno-deprecated-copy -std=c++17
CFLAGS += $(COMMON_OPT) -Wall -Wextra

ifeq ($(shell uname -m),x86_64)
    CXXFLAGS += -march=native -mtune=native -msse2 -msse3
    CFLAGS += -march=native -mtune=native -msse2 -msse3
else
    CXXFLAGS += -fomit-frame-pointer -DNO_SIMD
    CFLAGS += -fomit-frame-pointer -DNO_SIMD
endif

LIBS = -lm -lpthread
LEGACY_LIBS = -lm -lpthread -lcrypto -lgmp

default:
	$(CXX) $(CXXFLAGS) -c oldbloom/bloom.cpp -o oldbloom.o
	$(CXX) $(CXXFLAGS) -c bloom/bloom.cpp -o bloom.o
	$(CC) $(CFLAGS) -Wno-unused-parameter -c base58/base58.c -o base58.o
	$(CC) $(CFLAGS) -c rmd160/rmd160.c -o rmd160.o
	$(CXX) $(CXXFLAGS) -c sha3/sha3.c -o sha3.o
	$(CXX) $(CXXFLAGS) -c sha3/keccak.c -o keccak.o
	$(CC) $(CFLAGS) -c xxhash/xxhash.c -o xxhash.o
	$(CXX) $(CXXFLAGS) -c util.c -o util.o
	$(CXX) $(CXXFLAGS) -c secp256k1/Int.cpp -o Int.o
	$(CXX) $(CXXFLAGS) -c secp256k1/Point.cpp -o Point.o
	$(CXX) $(CXXFLAGS) -c secp256k1/SECP256K1.cpp -o SECP256K1.o
	$(CXX) $(CXXFLAGS) -c secp256k1/IntMod.cpp -o IntMod.o
	$(CXX) $(CXXFLAGS) -c secp256k1/Random.cpp -o Random.o
	$(CXX) $(CXXFLAGS) -c secp256k1/IntGroup.cpp -o IntGroup.o
	$(CXX) $(CXXFLAGS) -c hash/ripemd160.cpp -o hash/ripemd160.o
	$(CXX) $(CXXFLAGS) -c hash/sha256.cpp -o hash/sha256.o
	$(CXX) $(CXXFLAGS) -c hash/ripemd160_sse.cpp -o hash/ripemd160_sse.o
	$(CXX) $(CXXFLAGS) -c hash/sha256_sse.cpp -o hash/sha256_sse.o
	$(CXX) $(CXXFLAGS) -o keyhunt keyhunt.cpp base58.o rmd160.o hash/ripemd160.o hash/ripemd160_sse.o hash/sha256.o hash/sha256_sse.o bloom.o oldbloom.o xxhash.o util.o Int.o Point.o SECP256K1.o IntMod.o Random.o IntGroup.o sha3.o keccak.o $(LIBS)
	rm -f *.o

legacy:
	$(CXX) $(CXXFLAGS) -c oldbloom/bloom.cpp -o oldbloom.o
	$(CXX) $(CXXFLAGS) -c bloom/bloom.cpp -o bloom.o
	$(CC) $(CFLAGS) -Wno-unused-result -c base58/base58.c -o base58.o
	$(CC) $(CFLAGS) -c xxhash/xxhash.c -o xxhash.o
	$(CXX) $(CXXFLAGS) -c util.c -o util.o
	$(CXX) $(CXXFLAGS) -c sha3/sha3.c -o sha3.o
	$(CXX) $(CXXFLAGS) -c sha3/keccak.c -o keccak.o
	$(CXX) $(CXXFLAGS) -c hashing.c -o hashing.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/Int.cpp -o Int.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/Point.cpp -o Point.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/GMP256K1.cpp -o GMP256K1.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/IntMod.cpp -o IntMod.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/Random.cpp -o Random.o
	$(CXX) $(CXXFLAGS) -c gmp256k1/IntGroup.cpp -o IntGroup.o
	$(CXX) $(CXXFLAGS) -o keyhunt keyhunt_legacy.cpp base58.o bloom.o oldbloom.o xxhash.o util.o Int.o Point.o GMP256K1.o IntMod.o IntGroup.o Random.o hashing.o sha3.o keccak.o $(LEGACY_LIBS)
	rm -f *.o

bsgsd:
	$(CXX) $(CXXFLAGS) -c oldbloom/bloom.cpp -o oldbloom.o
	$(CXX) $(CXXFLAGS) -c bloom/bloom.cpp -o bloom.o
	$(CC) $(CFLAGS) -Wno-unused-parameter -c base58/base58.c -o base58.o
	$(CC) $(CFLAGS) -c rmd160/rmd160.c -o rmd160.o
	$(CXX) $(CXXFLAGS) -c sha3/sha3.c -o sha3.o
	$(CXX) $(CXXFLAGS) -c sha3/keccak.c -o keccak.o
	$(CC) $(CFLAGS) -c xxhash/xxhash.c -o xxhash.o
	$(CXX) $(CXXFLAGS) -c util.c -o util.o
	$(CXX) $(CXXFLAGS) -c secp256k1/Int.cpp -o Int.o
	$(CXX) $(CXXFLAGS) -c secp256k1/Point.cpp -o Point.o
	$(CXX) $(CXXFLAGS) -c secp256k1/SECP256K1.cpp -o SECP256K1.o
	$(CXX) $(CXXFLAGS) -c secp256k1/IntMod.cpp -o IntMod.o
	$(CXX) $(CXXFLAGS) -c secp256k1/Random.cpp -o Random.o
	$(CXX) $(CXXFLAGS) -c secp256k1/IntGroup.cpp -o IntGroup.o
	$(CXX) $(CXXFLAGS) -c hash/ripemd160.cpp -o hash/ripemd160.o
	$(CXX) $(CXXFLAGS) -c hash/sha256.cpp -o hash/sha256.o
	$(CXX) $(CXXFLAGS) -c hash/ripemd160_sse.cpp -o hash/ripemd160_sse.o
	$(CXX) $(CXXFLAGS) -c hash/sha256_sse.cpp -o hash/sha256_sse.o
	$(CXX) $(CXXFLAGS) -o bsgsd bsgsd.cpp base58.o rmd160.o hash/ripemd160.o hash/ripemd160_sse.o hash/sha256.o hash/sha256_sse.o bloom.o oldbloom.o xxhash.o util.o Int.o Point.o SECP256K1.o IntMod.o Random.o IntGroup.o sha3.o keccak.o $(LIBS)
	rm -f *.o

clean:
	rm -f keyhunt bsgsd
