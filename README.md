# keyhunt
privkey hunt for crypto currencies that use secp256k1  elliptic curve

Work for btc in this moment, only legacy Addresses that start with '1'

Ethereum addresses is a work in develop

# How to use
First compile:

``make``

and then execute:

``./keyhunt``

you need to have tome file called **adddress.txt** or specify other file with the **-f** opcion

``./keyhunt -f ~/some/path/to/other/file.txt``

if you want more thereads use the **-t** option

``./keyhunt -f ~/some/path/to/other/file.txt -t 8``

if you want to know the full help just use **-h** param

``./keyhunt -h``

al the hunted keys are saved in a file keys.txt

The default behaivor ot keyhunt is to choose a random key and check secuentialy for the next 4.2 billions keys, this is **4294967295** or **0xffffffff**

# BSGS ( Baby step giant step)

The new version of keyhunt implement the bsgs algorithm to search privatekeys for a knowed publickey.

The address.txt file need to have a 130 hexadecimal characters uncompress publickey per line any other word followed by an space is ignored example of the file:

```
043ffa1cc011a8d23dec502c7656fb3f93dbe4c61f91fd443ba444b4ec2dd8e6f0406c36edf3d8a0dfaa7b8f309b8f1276a5c04131762c23594f130a023742bdde # 0000000000000000000000000000000000800000000000000000100000000000
046534b9e9d56624f5850198f6ac462f482fec8a60262728ee79a91cac1d60f8d6a92d5131a20f78e26726a63d212158b20b14c3025ebb9968c890c4bab90bfc69 # 0000000000000000000000000000000000800000000000000000200000000000
```

This example contains 2 publickeys followed by his privatekey just to test the correct behaivor of the application

btw any word followed by and space after the publickey is ignored the file can be only the publickeys:

```
043ffa1cc011a8d23dec502c7656fb3f93dbe4c61f91fd443ba444b4ec2dd8e6f0406c36edf3d8a0dfaa7b8f309b8f1276a5c04131762c23594f130a023742bdde
046534b9e9d56624f5850198f6ac462f482fec8a60262728ee79a91cac1d60f8d6a92d5131a20f78e26726a63d212158b20b14c3025ebb9968c890c4bab90bfc69
```

To try to find those privatekey this is the line of execution:

`` ./keyhunt -m bsgs -f test_120.txt -r 800000000000000000000000000000:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF ``

Output:

```
$ ./keyhunt -m bsgs -f test_120.txt -r 800000000000000000000000000000:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
[+] Version 0.1.20210112 BSGS
[+] Setting mode BSGS
[+] Opening file test_120.txt
[+] Added 2 points from file
[+] Setting N up to 17592186044416.
[+] Init bloom filter for 4194304 elements : 7.00 MB
[+] Allocating 128.00 MB for aMP Points
[+] Precalculating 4194304 aMP points
[+] Allocating 144.00 MB for bP Points
[+] precalculating 4194304 bP points
[+] Sorting 4194304 elements
[+] Thread 0: 0000000000000000000000000000000000800000000000000000000000000000
[+] Thread 0 Key found privkey 0000000000000000000000000000000000800000000000000000100000000000
[+] Publickey 043ffa1cc011a8d23dec502c7656fb3f93dbe4c61f91fd443ba444b4ec2dd8e6f0406c36edf3d8a0dfaa7b8f309b8f1276a5c04131762c23594f130a023742bdde
[+] Thread 0: 0000000000000000000000000000000000800000000000000000100000000000
Total 17592186044416 keys in 30 seconds: 586406201480 keys/s
[+] Thread 0 Key found privkey 0000000000000000000000000000000000800000000000000000200000000000
[+] Publickey 046534b9e9d56624f5850198f6ac462f482fec8a60262728ee79a91cac1d60f8d6a92d5131a20f78e26726a63d212158b20b14c3025ebb9968c890c4bab90bfc69
All points were found
```

Test the puzzle 120 with the next publickey:

```
04ceb6cbbcdbdf5ef7150682150f4ce2c6f4807b349827dcdbdd1f2efa885a26302b195386bea3f5f002dc033b92cfc2c9e71b586302b09cfe535e1ff290b1b5ac # Compressed Address : 17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT
```

Line of execution in random mode **-R**
``./keyhunt -m bsgs -f 120.txt -r 800000000000000000000000000000:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -R`` 


Example Output:

```
$ ./keyhunt -m bsgs -f 120.txt -r 800000000000000000000000000000:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -R
[+] Version 0.1.20210112 BSGS
[+] Setting mode BSGS
[+] Setting random mode.
[+] Opening file 120.txt
[+] Added 1 points from file
[+] Setting N up to 17592186044416.
[+] Init bloom filter for 4194304 elements : 7.00 MB
[+] Allocating 128.00 MB for aMP Points
[+] Precalculating 4194304 aMP points
[+] Allocating 144.00 MB for bP Points
[+] precalculating 4194304 bP points
[+] Sorting 4194304 elements
[+] Thread 0: 0000000000000000000000000000000000d80083712e9650075586dd5e162d44
[+] Thread 0: 0000000000000000000000000000000000f92eb8e27b7fb1bd2ec4eb4ac223a1
[+] Thread 0: 0000000000000000000000000000000000dda9ebacc83b0f0d1d36829fcc17b7
Total 35184372088832 keys in 30 seconds: 1172812402961 keys/s
[+] Thread 0: 0000000000000000000000000000000000ac445f232e0207b9cf46b73e106fed
```

Good speed no? 1.1 Terakeys/s for one single thread

**Total 35184372088832 keys in 30 seconds: 1172812402961 keys/s**

We can speed up our process selecting a bigger n value **-n value** btw the n value is the total length of item tested in the radom range, and bigger n value means more ram to be use:

Example:
``$ ./keyhunt -m bsgs -f 120.txt -r 800000000000000000000000000000:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -R -n 1000000000000000 -s 120``

Example output:

```
$ ./keyhunt -m bsgs -f 120.txt -r 800000000000000000000000000000:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -R -n 1000000000000000 -s 120
[+] Version 0.1.20210112 BSGS
[+] Setting mode BSGS
[+] Setting random mode.
[+] Stats output every 120 seconds
[+] Opening file 120.txt
[+] Added 1 points from file
[+] Setting N up to 1000000025191729.
[+] Init bloom filter for 31622777 elements : 54.00 MB
[+] Allocating 965.00 MB for aMP Points
[+] Precalculating 31622777 aMP points
[+] Allocating 1085.00 MB for bP Points
[+] precalculating 31622777 bP points
[+] Sorting 31622777 elements
[+] Thread 0: 0000000000000000000000000000000000f7e37bb1f8b39dc749ff0c6be2b918
[+] Thread 0: 0000000000000000000000000000000000fe37e21c957baf3823262cf7270d67
Total 1000000025191729 keys in 120 seconds: 8333333543264 keys/s
[+] Thread 0: 0000000000000000000000000000000000af1723ee0314a3381a58b5421bce63
Total 2000000050383458 keys in 240 seconds: 8333333543264 keys/s

```

**8.3 Terakeys/s for one single thread**

Please be careful with the n value and test it first by you own, againts a knowed publickey/privatekey, some values of n are bugging and I need to solve the errors, please report any extrage behaivor of the tool.

# Dependencies
- libgmp
- pthread

Tested under Debian
