default:
	gcc -O3 -c bloom/bloom.c -o bloom.o
	g++ -O3 -c sha256/sha256.c -o sha256.o
	gcc -O3 -c base58/base58.c -o base58.o
	gcc -O3 -c rmd160/rmd160.c -o rmd160.o
	gcc -O3 -c sha3/sha3.c -o sha3.o
	gcc -O3 -c xxhash/xxhash.c -o xxhash.o
	g++ -O3 -c util.c -o util.o
	g++ -m64 -mssse3 -Wno-unused-result -Wno-write-strings -O2 -c secp256k1/Int.cpp -o Int.o
	g++ -m64 -mssse3 -Wno-unused-result -Wno-write-strings -O2 -c secp256k1/Point.cpp -o Point.o
	g++ -m64 -mssse3 -Wno-unused-result -Wno-write-strings -O2 -c secp256k1/SECP256K1.cpp -o SECP256K1.o
	g++ -m64 -mssse3 -Wno-unused-result -Wno-write-strings -O2 -c secp256k1/IntMod.cpp -o IntMod.o
	g++ -m64 -mssse3 -Wno-unused-result -Wno-write-strings -O2 -c secp256k1/Random.cpp -o Random.o
	g++ -m64 -mssse3 -Wno-unused-result -Wno-write-strings -O2 -c secp256k1/IntGroup.cpp -o IntGroup.o
	g++ -o keyhunt keyhunt.c base58.o rmd160.o sha256.o bloom.o xxhash.o util.o Int.o  Point.o SECP256K1.o  IntMod.o  Random.o IntGroup.o -lgmp -lm -lpthread
	#gcc -O3 hexcharstoraw.c -o hexcharstoraw util.o -lm
	g++ -o bPfile bPfile.c util.o -lgmp -lm
clean:
	rm -r *.o
