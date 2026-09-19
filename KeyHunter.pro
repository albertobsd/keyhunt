TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

win32 {

    #QMAKE_CFLAGS_RELEASE  += /TP
    #QMAKE_CXXFLAGS_RELEASE  += /TP

}


SOURCES += \
        keyhunt.cpp                       \
        oldbloom/bloom.cpp                \
        bloom/bloom.cpp                   \
        base58/base58.c                   \
        rmd160/rmd160.c                   \
        sha3/sha3.c                       \
        sha3/keccak.c                     \
        xxhash/xxhash.c                   \
        util.c                            \
        secp256k1/Int.cpp                 \
        secp256k1/Point.cpp               \
        secp256k1/SECP256K1.cpp           \
        secp256k1/IntMod.cpp              \
        secp256k1/Random.cpp              \
        secp256k1/IntGroup.cpp            \
        hash/ripemd160.cpp                \
        hash/sha256.cpp                   \
        hash/ripemd160_sse.cpp            \
        hash/sha256_sse.cpp


HEADERS += \
        keyhunt.h                         \
        oldbloom/bloom.h                  \
        bloom/bloom.h                     \
        base58/base58.h                   \
        rmd160/rmd160.h                   \
        sha3/sha3.h                       \
        sha3/keccak.h                     \
        xxhash/xxhash.h                   \
        util.h                            \
        secp256k1/Int.h                   \
        secp256k1/Point.h                 \
        secp256k1/SECP256K1.h             \
        secp256k1/IntMod.h                \
        secp256k1/Random.h                \
        secp256k1/IntGroup.h              \
        hash/ripemd160.h                  \
        hash/sha256.h                     \
        hash/ripemd160_sse.h              \
        hash/sha256_sse.h  

