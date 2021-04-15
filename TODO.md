#TODO
- Implement the new way to genetatekey to mode `bsgs` this will improve the speed of bsgs ten times more.
- GPU support
- Make a test files for All cases of input data with fixed ranges of search
- address BTC legacy, bech32, ETH

#DONE
- Optimize Point Addition, maybe with a custom bignumber lib instead libgmp
  This was done in the version `0.1.20210412 secp256k1` we change from libgmp to secp256k1
- Added sha3 same files used by brainflayer
- Added mode rmd160
- Fixed the bug in Partition process of Introsort
- Fixed Quicksort edges cases (All data already sorted)
  To fix it Introsort was inmplement
- Fixed bottleneck of Point - Scalar multiplication
  This was fix implementing a fixed Doubling Point G
  Also part of this was made by bypassing it and implementing Point addition
