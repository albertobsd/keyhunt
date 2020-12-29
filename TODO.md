#TODO
- Implement libkeccak at https://github.com/maandree/libkeccak
  This is the only library that implement legacy keccak funtion (NOT SHA3)
  See https://medium.com/@ConsenSys/are-you-really-using-sha-3-or-old-code-c5df31ad2b0 as reference
- GPU support
- Optimize Point Addition, maybe with a custom bignumber lib instead libgmp
- Fix a minor bug in Partition process of Introsort
  fixing this will half the time of sorting data
- Make a test files for All cases of input data with fixed ranges of search
  - address BTC legacy, bech32, ETH
  - xpoint hexchars and binary


#DONE
- Fixed Quicksort edges cases (All data already sorted)
  To fix it Introsort was inmplement
- Fixed bottleneck of Point - Scalar multiplication
  This was fix implementing a fixed Doubling Point G
  Also part of this was made by bypassing it and implementing Point addition

