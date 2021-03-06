#Version 0.1.20210306 K*BSGS
- Added K factor for BSGS
- Added bPfile.c to generate a precalculated file
- Remove unused files about keccak and sha3

#Version 0.1.20210112 BSGS
- Added mode BSGS this work with a file with uncompressed keys
- Updated  bloom filter to allow More items


#Version 0.1.20201228
- Change Quicksort to Introsort, this solve some edge cases of quicksort.
- Introsort is avaible to keyhunt and hexcharstoraw. worst case. O(N log N).
- Aling of some output text

#Version 0.1.20201223
- Added new tool hexcharstoraw to create a raw binary file for xpoint from a text-hexadecimal file
- Added option -w to work with raw binary file, this file contains xpoint in binary format fixed to 32 bytes

#Version 0.1.20201222
- Fixed some ugly bug in the searchbinary function thanks to Ujang
- Added to stdout the vanitykeys found with -v option

#Version 0.1.20201221
- Fixed search by xpoint.
- Added -e option to skip the sort process whe the file is already sorted.
- Fixed debugcount when upto N is less than debugcount.
- Changed "-R upto" to "-R" and added "-n upto" option.

#Version 0.1.20201218
- Minor bugs fixed.

#Version 0.1.20201217
- First Realease
- Thanks to all CryptoHunters to make this code possible
