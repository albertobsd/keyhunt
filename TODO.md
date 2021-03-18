#TODO
- GPU support
- Optimize Point Addition, maybe with a custom bignumber lib instead libgmp
- Make a test files for All cases of input data with fixed ranges of search
  - address BTC legacy, bech32, ETH

#DONE
- Added sha3 same files used by brainflayer
- Added mode rmd160
- Fixed the bug in Partition process of Introsort
- Fixed Quicksort edges cases (All data already sorted)
  To fix it Introsort was inmplement
- Fixed bottleneck of Point - Scalar multiplication
  This was fix implementing a fixed Doubling Point G
  Also part of this was made by bypassing it and implementing Point addition

