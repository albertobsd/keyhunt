default:
	gcc -O3 -c bloom/bloom.c -o bloom.o -I./bloom/murmur2
	gcc -O3 -c bloom/murmur2/MurmurHash2.c -o murmurhash2.o
	gcc -O3 -c sha256/sha256.c -o sha256.o
	gcc -O3 -c base58/base58.c -o base58.o
	gcc -O3 -c rmd160/rmd160.c -o rmd160.o
	gcc -O3 -c keyhunt.c -o keyhunt.o -lm
	gcc -o keyhunt keyhunt.o base58.o rmd160.o sha256.o bloom.o murmurhash2.o -lgmp -lm -lpthread
	gcc -O3 hexcharstoraw.c -o hexcharstoraw -lm
	gcc -o bPfile bPfile.c -lgmp -lm
clean:
	rm -r *.o
