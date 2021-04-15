# Version 0.1.20210412 secp256k1
- Full migration from libgmp to secp256k1
- Change the way for keygeneration for modes xpoint, address, and rmd160
- Improve performance for xpoint mode, now is ten times faster
- Change N variable type for modes address,rmd160 and xpoint, from uint32_t to uint64_t
- Added method pub2rmd to search publickeys of the puzzles and other legacy address (Compress publickeys only)

# Version 0.1.20210331
- Small changes to be compiled with mingw on Windows
- Changed sort functions and binary search for modes address/rmd160/xpoint, now those modes can load MAX 2^64 items
- xpoint input file now can contains Comments after the line of data
- from this version all furthers developments will be in the branch `development`

# Version 0.1.20210328
- Added a progress counter (this solve bug https://github.com/albertobsd/keyhunt/issues/18 )
- Added multithread for precalculating bP items or reading then from file
- Fixed the code to avoid warnings (this solve the issue https://github.com/albertobsd/keyhunt/issues/19)

# Version 0.1.20210322
- Added xxhash for bloomfilter this hash have better performance than murmurhash2. And it is 64 bits hash :)
- We reduce the number of items of the bPtable in ram using a second bloom filter, thanks @iceland2k14
- The ram saved space is around 80%, so we can use a bigger K value, around 4 or 5 times bigger than previous version

# Version 0.1.20210320 K*BSGS
- Solved little error with compress and uncompress new param -l. See https://github.com/albertobsd/keyhunt/issues/17
- function bsgs optimized to use a little less RAM (not related with Pfile)
- Again removed some compile warnings. See https://github.com/albertobsd/keyhunt/issues/16

# Version 0.1.20210311 K*BSGS
- Added mode rmd160, this method works two times faster than Address method. This mode can search all the altcoins


# Version 0.1.20210311 K*BSGS
- Solved some bug when the publickeys in the input file was invalid but the program keeps running with 0 publickeys
- Now publickeys can be compressed, not only uncompressed

# Version 0.1.20210306 K*BSGS
- Added K factor for BSGS
- Added bPfile.c to generate a precalculated file
- Remove unused files about keccak and sha3
- Change Bloom filter limits and % of error from 0.001 to 0.00001 in bloomfilter.

# Version 0.1.20210112 BSGS
- Added mode BSGS this work with a file with uncompressed keys
- Updated  bloom filter to allow More items

# Version 0.1.20201228
- Change Quicksort to Introsort, this solve some edge cases of quicksort.
- Introsort is avaible to keyhunt and hexcharstoraw. worst case. O(N log N).
- Aling of some output text

# Version 0.1.20201223
- Added new tool hexcharstoraw to create a raw binary file for xpoint from a text-hexadecimal file
- Added option -w to work with raw binary file, this file contains xpoint in binary format fixed to 32 bytes

# Version 0.1.20201222
- Fixed some ugly bug in the searchbinary function thanks to Ujang
- Added to stdout the vanitykeys found with -v option

# Version 0.1.20201221
- Fixed search by xpoint.
- Added -e option to skip the sort process whe the file is already sorted.
- Fixed debugcount when upto N is less than debugcount.
- Changed "-R upto" to "-R" and added "-n upto" option.

# Version 0.1.20201218
- Minor bugs fixed.

# Version 0.1.20201217
- First Release
- Thanks to all CryptoHunters to make this code possible
