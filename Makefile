default:
	g++ -m64 -Ofast -march=native -funroll-loops -flto -c oldbloom/bloom.cpp -o oldbloom.o
	g++ -m64 -Ofast -march=native -funroll-loops -flto -c bloom/bloom.cpp -o bloom.o
#	g++ -Ofast -c sha256/sha256.c -o sha256.o
	gcc -m64 -Ofast -march=native -funroll-loops -flto -c base58/base58.c -o base58.o
	gcc -m64 -Ofast -march=native -funroll-loops -flto -c rmd160/rmd160.c -o rmd160.o
	g++ -m64 -Ofast -march=native -funroll-loops -flto -c sha3/sha3.c -o sha3.o
	g++ -m64 -Ofast -march=native -funroll-loops -flto -c sha3/keccak.c -o keccak.o
	gcc -m64 -Ofast -march=native -funroll-loops -flto -c xxhash/xxhash.c -o xxhash.o
	g++ -m64 -Ofast -march=native -funroll-loops -flto -c util.c -o util.o
	g++ -m64 -march=native -Wno-unused-result -Wno-write-strings -Ofast -c secp256k1/Int.cpp -o Int.o
	g++ -m64 -march=native -Wno-unused-result -Wno-write-strings -Ofast -c secp256k1/Point.cpp -o Point.o
	g++ -m64 -march=native -Wno-unused-result -Wno-write-strings -Ofast -c secp256k1/SECP256K1.cpp -o SECP256K1.o
	g++ -m64 -march=native -Wno-unused-result -Wno-write-strings -Ofast -c secp256k1/IntMod.cpp -o IntMod.o
	g++ -m64 -march=native -Wno-unused-result -Wno-write-strings -Ofast -c secp256k1/Random.cpp -o Random.o
	g++ -m64 -march=native -Wno-unused-result -Wno-write-strings -Ofast -c secp256k1/IntGroup.cpp -o IntGroup.o
	g++ -m64 -march=native -Wno-write-strings -Ofast -o hash/ripemd160.o -c hash/ripemd160.cpp
	g++ -m64 -march=native -Wno-write-strings -Ofast -o hash/sha256.o -c hash/sha256.cpp
	g++ -m64 -march=native -Wno-write-strings -Ofast -o hash/ripemd160_sse.o -c hash/ripemd160_sse.cpp
	g++ -m64 -march=native -Wno-write-strings -Ofast -o hash/sha256_sse.o -c hash/sha256_sse.cpp
	g++ -m64 -Ofast -march=native -funroll-loops -flto -o keyhunt keyhunt.cpp base58.o rmd160.o  hash/ripemd160.o hash/ripemd160_sse.o hash/sha256.o hash/sha256_sse.o bloom.o oldbloom.o xxhash.o util.o Int.o  Point.o SECP256K1.o  IntMod.o  Random.o IntGroup.o sha3.o keccak.o  -lm -pthread
	rm -r *.o
clean:
	rm keyhunt