# keyhunt
Tool for hunt privatekeys for crypto currencies that use secp256k1  elliptic curve

Post: https://bitcointalk.org/index.php?topic=5322040.0

Work for btc in this moment, only legacy Addresses that start with '1'

Ethereum addresses is a work in develop

# Download

To clone the repository:

`git clone https://github.com/albertobsd/keyhunt.git`

don't forget change to the keyhunt directory

`cd keyhunt`

# How to build
First compile:

`make`

and then execute:

`./keyhunt -h`

# Modes

Keyhunt can work in diferents ways at different speeds.
The current availables modes are:
- address
- rmd160
- xpoint
- bsgs

## address mode

This is the most basic approach to work, in this mode your text file need to have a list of the publicaddress to be search.

Example of address from solved puzzles, this file is already on the repository `tests/1to32.txt`

```
1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb
19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA
1EhqbyUMvvs7BfL8goY6qcPbD6YKfPqb7e
1E6NuFjCi27W5zoXg8TRdcSRq84zJeBW3k
1PitScNLyp2HCygzadCh7FveTnfmpPbfp8
1McVt1vMtCC7yn5b9wgX1833yCcLXzueeC
1M92tSqNmQLYw33fuBvjmeadirh1ysMBxK
1CQFwcjw1dwhtkVWBttNLDtqL7ivBonGPV
1LeBZP5QCwwgXRtmVUvTVrraqPUokyLHqe
1PgQVLmst3Z314JrQn5TNiys8Hc38TcXJu
1DBaumZxUkM4qMQRt2LVWyFJq5kDtSZQot
1Pie8JkxBT6MGPz9Nvi3fsPkr2D8q3GBc1
1ErZWg5cFCe4Vw5BzgfzB74VNLaXEiEkhk
1QCbW9HWnwQWiQqVo5exhAnmfqKRrCRsvW
1BDyrQ6WoF8VN3g9SAS1iKZcPzFfnDVieY
1HduPEXZRdG26SUT5Yk83mLkPyjnZuJ7Bm
1GnNTmTVLZiqQfLbAdp9DVdicEnB5GoERE
1NWmZRpHH4XSPwsW6dsS3nrNWfL1yrJj4w
1HsMJxNiV7TLxmoF6uJNkydxPFDog4NQum
14oFNXucftsHiUMY8uctg6N487riuyXs4h
1CfZWK1QTQE3eS9qn61dQjV89KDjZzfNcv
1L2GM8eE7mJWLdo3HZS6su1832NX2txaac
1rSnXMr63jdCuegJFuidJqWxUPV7AtUf7
15JhYXn6Mx3oF4Y7PcTAv2wVVAuCFFQNiP
1JVnST957hGztonaWK6FougdtjxzHzRMMg
128z5d7nN7PkCuX5qoA4Ys6pmxUYnEy86k
12jbtzBb54r97TCwW3G1gCFoumpckRAPdY
19EEC52krRUK1RkUAEZmQdjTyHT7Gp1TYT
1LHtnpd8nU5VHEMkG2TMYYNUjjLc992bps
1LhE6sCTuGae42Axu1L1ZB7L96yi9irEBE
1FRoHA9xewq7DjrZ1psWJVeTer8gHRqEvR
```

To target that file we need to execute keyhunt with this line

`./keyhunt -m address -f tests/1to32.txt -r 1:FFFFFFFF`

output:
```
[+] Version 0.1.20210328
[+] Setting mode address
[+] Opening file tests/1to32.txt
[+] Setting search for btc adddress
[+] Allocating memory for 32 elements: 0.00 MB
[+] Initializing bloom filter for 32 elements.
[+] Loading data to the bloomfilter
[+] Bloomfilter completed
[+] Sorting data
[+] 32 values were loaded and sorted
Thread 0 : Setting up base key: 0000000000000000000000000000000000000000000000000000000000000001
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000001
pubkey: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000003
pubkey: 02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
address: 1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000007
pubkey: 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc
address: 19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000008
pubkey: 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01
address: 1EhqbyUMvvs7BfL8goY6qcPbD6YKfPqb7e
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000015
pubkey: 02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5
address: 1E6NuFjCi27W5zoXg8TRdcSRq84zJeBW3k
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000031
pubkey: 03f2dac991cc4ce4b9ea44887e5c7c0bce58c80074ab9d4dbaeb28531b7739f530
address: 1PitScNLyp2HCygzadCh7FveTnfmpPbfp8
(Output omitted)
```

In this mode you can specify to seach only address compressed or uncompressed with `-l compress` o  `-l compress`

Test your look with the random parameter `-R` againts the puzzle #64

`./keyhunt -m address -f tests/64.txt -b 64 -l compress -R`

Please note the change from `-r 1:FFFFFFFF` to `-b 64`, with -b you can specify the bit range

output:
```
[+] Version 0.1.20210328
[+] Setting mode address
[+] Min range: 8000000000000000
[+] Max range: ffffffffffffffff
[+] Search compress only
[+] Setting random mode.
[+] Opening file tests/64.txt
[+] Setting search for btc adddress
[+] Allocating memory for 1 elements: 0.00 MB
[+] Initializing bloom filter for 1 elements.
[+] Loading data to the bloomfilter
[+] Bloomfilter completed
[+] Sorting data
[+] 1 values were loaded and sorted
Thread 0 : Setting up base key: 000000000000000000000000000000000000000000000000adf754734f7cf61a
Total 26214400 keys in 150 seconds: 174762 keys/s
(Output omitted)
```

## rmd160 mode

rmd stand for RIPE Message Digest (see https://en.wikipedia.org/wiki/RIPEMD )

mode rmd160 work in the same way than address, but the diference is that file need to have hash rmd160 instead of addresses.

This mode is almost two times faster than addres mode

example:

```
751e76e8199196d454941c45d1b3a323f1433bd6
7dd65592d0ab2fe0d0257d571abf032cd9db93dc
5dedfbf9ea599dd4e3ca6a80b333c472fd0b3f69
9652d86bedf43ad264362e6e6eba6eb764508127
8f9dff39a81ee4abcbad2ad8bafff090415a2be8
f93ec34e9e34a8f8ff7d600cdad83047b1bcb45c
e2192e8a7dd8dd1c88321959b477968b941aa973
dce76b2613052ea012204404a97b3c25eac31715
7d0f6c64afb419bbd7e971e943d7404b0e0daab4
d7729816650e581d7462d52ad6f732da0e2ec93b
f8c698da3164ef8fa4258692d118cc9a902c5acc
85a1f9ba4da24c24e582d9b891dacbd1b043f971
f932d0188616c964416b91fb9cf76ba9790a921e
97f9281a1383879d72ac52a6a3e9e8b9a4a4f655
fe7c45126731f7384640b0b0045fd40bac72e2a2
7025b4efb3ff42eb4d6d71fab6b53b4f4967e3dd
b67cb6edeabc0c8b927c9ea327628e7aa63e2d52
ad1e852b08eba53df306ec9daa8c643426953f94
ebfbe6819fcdebab061732ce91df7d586a037dee
b907c3a2a3b27789dfb509b730dd47703c272868
29a78213caa9eea824acf08022ab9dfc83414f56
7ff45303774ef7a52fffd8011981034b258cb86b
d0a79df189fe1ad5c306cc70497b358415da579e
0959e80121f36aea13b3bad361c15dac26189e2f
2f396b29b27324300d0c59b17c3abc1835bd3dbb
bfebb73562d4541b32a02ba664d140b5a574792f
0c7aaf6caa7e5424b63d317f0f8f1f9fa40d5560
1306b9e4ff56513a476841bac7ba48d69516b1da
5a416cc9148f4a377b672c8ae5d3287adaafadec
d39c4704664e1deb76c9331e637564c257d68a08
d805f6f251f7479ebd853b3d0f4b9b2656d92f1d
9e42601eeaedc244e15f17375adb0e2cd08efdc9
```

to target that file you need to execute the next line:

`./keyhunt -m rmd160 -f tests/1to32.rmd -r 1:FFFFFFFF -l compress`

output:

```
[+] Version 0.1.20210328
[+] Setting mode rmd160
[+] Search compress only
[+] Opening file tests/1to32.rmd
[+] Allocating memory for 32 elements: 0.00 MB
[+] Initializing bloom filter for 32 elements.
[+] Loading data to the bloomfilter
[+] Bloomfilter completed
[+] Sorting data
[+] 32 values were loaded and sorted
Thread 0 : Setting up base key: 0000000000000000000000000000000000000000000000000000000000000001HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000001
pubkey: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000003
pubkey: 02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000007
pubkey: 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000008
pubkey: 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000015
pubkey: 02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5
HIT!! PrivKey: 0000000000000000000000000000000000000000000000000000000000000031
(Output omited)
```

test your luck with the next file for th puzzle #64

`./keyhunt -m rmd160 -f tests/64.rmd -b 64 -l compress -R`

Output:

```
[+] Version 0.1.20210328
[+] Setting mode rmd160
[+] Min range: 8000000000000000
[+] Max range: ffffffffffffffff
[+] Search compress only
[+] Setting random mode.
[+] Opening file tests/64.rmd
[+] Allocating memory for 1 elements: 0.00 MB
[+] Initializing bloom filter for 1 elements.
[+] Loading data to the bloomfilter
[+] Bloomfilter completed
[+] Sorting data
[+] 1 values were loaded and sorted
Thread 0 : Setting up base key: 000000000000000000000000000000000000000000000000f7d1beda50ed79d4
Total 27262976 keys in 120 seconds: 227191 keys/s
(Output omited)
```

BTW this rmd160 mode doesn't allow search by vanity address

## xpoint mode

This method can target the X value of the publickey in the same way that the tool search for address or rmd160 hash, this tool can search for the X values

The speed for this method is is better than the speed for address or rmd160

The input file can had one publickey per line compress or uncompress:

- Publickey Compress (66 hexcharacters)
- Publickey Uncompress (130 hexcharacters)

Example input file:

A few substracted values from puzzle *40*

```
034eee474fe724cb631d19f24934e88016e4ef2aee80d086621d87d7f6066ff860 # - 453856235784
0274241b684e7c31e7933510b510aa14de9ac88ec3635bdd35a3bcf1d16da210be # + 453856235784
03abc6aff092b9a64bf69e00f4ec7a8b7ca51cfc6656732cbbc9f5674925b88609 # - 529328067324
034f4fe33b02c202b732d278f90eedc635af6f3be8a93c8d1cb0a01f6399aab2a4 # + 529328067324
03716ff57705e6446ac3e217c8c8bd9e9c8e58547457a6fe93ac254c37fd48afcb # - 14711740067
02ffa0769b0459c64b41f59f93495063ae031de0b846180bee37f921f20e141f60 # + 14711740067
03de1df5d801bbd5e7d86577bf14950f732fd41e586945d06d19e0fdea41a37d62 # - 549755814000
038d3711fd681e26c05b2f0cd423fa596e15054024e40add24a93bfa0c630531f1 # + 549755814000
03a2efa402fd5268400c77c20e574ba86409ededee7c4020e4b9f0edbee53de0d4 # target
```


Now you can use keyhunt against some thousand values of the puzzle 40:

`./keyhunt -m xpoint -f tests/substracted40.txt -n 65536 -t 4 -b 40`

Output:

```
[+] Version 0.1.20210330a
[+] Setting mode xpoint
[+] Setting 4 threads
[+] Min range: 8000000000
[+] Max range: ffffffffff
[+] Opening file tests/substracted40.txt
[+] Allocating memory for 6003 elements: 0.11 MB
[+] Initializing bloom filter for 6003 elements.
[+] Loading data to the bloomfilter
[+] Bloomfilter completed
[+] Sorting data
[+] 6003 values were loaded and sorted
Thread 3 : Setting up base key: 0000000000000000000000000000000000000000000000000000008001d00000
Thread 0 : Setting up base key: 00000000000000000000000000000000000000000000000000000080025b0000
HIT!! PrivKey: 000000000000000000000000000000000000000000000000000000800258a2ce
pubkey: 0274241b684e7c31e7933510b510aa14de9ac88ec3635bdd35a3bcf1d16da210be
Thread 1 : Setting up base key: 0000000000000000000000000000000000000000000000000000008002910000^C
```

After the hit we need to search the substracted index and make a simple math operation to get the real privatek:

```
0274241b684e7c31e7933510b510aa14de9ac88ec3635bdd35a3bcf1d16da210be # + 453856235784
```
The Operation is `800258a2ce` hex (+/-) in this case + `453856235784` decimal equals to `E9AE4933D6`

This is an easy example, I been trying the puzzle 120 with more than 500 millions of substracted keys and no luck.

## pub2rmd mode
This method is made to try to get the puzzles publickey key it works a little more faster because it skip the EC Operations

The input file need to have the hash RMD160 of the address without publickey leaked:

```
3ee4133d991f52fdf6a25c9834e0745ac74248a4
20d45a6a762535700ce9e0b216e31994335db8a5
739437bb3dd6d1983e66629c5f08c70e52769371
e0b8a2baee1b77fc703455f39d51477451fc8cfc
61eb8a50c86b0584bb727dd65bed8d2400d6d5aa
f6f5431d25bbf7b12e8add9af5e3475c44a0a5b8
bf7413e8df4e7a34ce9dc13e2f2648783ec54adb
105b7f253f0ebd7843adaebbd805c944bfb863e4
9f1adb20baeacc38b3f49f3df6906a0e48f2df3d
86f9fea5cdecf033161dd2f8f8560768ae0a6d14
783c138ac81f6a52398564bb17455576e8525b29
35003c3ef8759c92092f8488fca59a042859018c
67671d5490c272e3ab7ddd34030d587738df33da
351e605fac813965951ba433b7c2956bf8ad95ce
20d28d4e87543947c7e4913bcdceaa16e2f8f061
24cef184714bbd030833904f5265c9c3e12a95a2
7c99ce73e19f9fbfcce4825ae88261e2b0b0b040
c60111ed3d63b49665747b0e31eb382da5193535
fbc708d671c03e26661b9c08f77598a529858b5e
38a968fdfb457654c51bcfc4f9174d6ee487bb41
5c3862203d1e44ab3af441503e22db97b1c5097e
9978f61b92d16c5f1a463a0995df70da1f7a7d2a
6534b31208fe6e100d29f9c9c75aac8bf06fbb38
463013cd41279f2fd0c31d0a16db3972bfffac8d
c6927a00970d0165327d0a6db7950f05720c295c
2da63cbd251d23c7b633cb287c09e6cf888b3fe4
578d94dc6f40fff35f91f6fba9b71c46b361dff2
7eefddd979a1d6bb6f29757a1f463579770ba566
c01bf430a97cbcdaedddba87ef4ea21c456cebdb
```

To target that file you need to do:

`./keyhunt -m pub2rmd -f tests/puzzleswopublickey.txt -q`

Output:

```
[+] Version 0.1.20210331
[+] Setting mode pub2rmd
[+] Set quiet thread output
[+] Opening file tests/puzzleswopublickey.txt
[+] Allocating memory for 29 elements: 0.00 MB
[+] Initializing bloom filter for 29 elements.
[+] Loading data to the bloomfilter total: 0.00 MB
[+] Bloomfilter completed
[+] Sorting data
[+] 29 values were loaded and sorted
Total 76546048 keys in 90 seconds: 850511 keys/s
```

You can let it run for a while together with others scripts, if you get one of those publickeys now you can target it with a better method like bsgs or another tools like kangaroo


## bsgs mode (baby step giant step)

Keyhunt implement the BSGS algorithm to search privatekeys for a knowed publickey.

The input file need to have a list of publickeys compress or uncompress those publickey can be mixed in the same file, one publickey per line and any other word followed by an space is ignored example of the file:

```
043ffa1cc011a8d23dec502c7656fb3f93dbe4c61f91fd443ba444b4ec2dd8e6f0406c36edf3d8a0dfaa7b8f309b8f1276a5c04131762c23594f130a023742bdde # 0000000000000000000000000000000000800000000000000000100000000000
046534b9e9d56624f5850198f6ac462f482fec8a60262728ee79a91cac1d60f8d6a92d5131a20f78e26726a63d212158b20b14c3025ebb9968c890c4bab90bfc69 # 0000000000000000000000000000000000800000000000000000200000000000
```

This example contains 2 publickeys followed by his privatekey just to test the correct behavior of the application

btw any word followed by and space after the publickey is ignored the file can be only the publickeys:

```
043ffa1cc011a8d23dec502c7656fb3f93dbe4c61f91fd443ba444b4ec2dd8e6f0406c36edf3d8a0dfaa7b8f309b8f1276a5c04131762c23594f130a023742bdde
046534b9e9d56624f5850198f6ac462f482fec8a60262728ee79a91cac1d60f8d6a92d5131a20f78e26726a63d212158b20b14c3025ebb9968c890c4bab90bfc69
```

To try to find those privatekey this is the line of execution:

``./keyhunt -m bsgs -f tests/test120.txt -b 120``

Output:

```
[+] Version 0.1.20210328
[+] Setting mode BSGS
[+] Min range: 800000000000000000000000000000
[+] Max range: ffffffffffffffffffffffffffffff
[+] Opening file tests/test120.txt
[+] Added 2 points from file
[+] Bit Range 120
[+] Setting N up to 17592186044416.
[+] Init 1st bloom filter for 4194304 elements : 14.00 MB
[+] Init 2nd bloom filter for 209716 elements : 0.00 MB
[+] Allocating 128.0 MB for 4194304 aMP Points
[+] Precalculating 4194304 aMP points
[+] Allocating 3.00 MB for 209716 bP Points
[+] processing 4194304/4194304 bP points : 100 %
[+] Sorting 209716 elements
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
02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630
```

Line of execution in random mode **-R**

`./keyhunt -m bsgs -f tests/120.txt -b 120 -R`


Example Output:

```
[+] Version 0.1.20210328
[+] Setting mode BSGS
[+] Min range: 800000000000000000000000000000
[+] Max range: ffffffffffffffffffffffffffffff
[+] Setting random mode.
[+] Opening file tests/120.txt
[+] Added 1 points from file
[+] Bit Range 120
[+] Setting N up to 17592186044416.
[+] Init 1st bloom filter for 4194304 elements : 14.00 MB
[+] Init 2nd bloom filter for 209716 elements : 0.00 MB
[+] Allocating 128.0 MB for 4194304 aMP Points
[+] Precalculating 4194304 aMP points
[+] Allocating 3.00 MB for 209716 bP Points
[+] processing 4194304/4194304 bP points : 100 %
[+] Sorting 209716 elements
[+] Thread 0: 0000000000000000000000000000000000d79219eeaef3d014d3effc55327b00
Total 35184372088832 keys in 30 seconds: 1172812402961 keys/s
```

Good speed no? 1.1 Terakeys/s for one single thread

**Total 70368744177664 keys in 60 seconds: 1172812402961 keys/s**

We can speed up our process selecting a bigger K value `-k value` btw the n value is the total length of item tested in the radom range, a bigger k value means more ram to be use:

Example:
`$ ./keyhunt -m bsgs -f tests/120.txt -b 120 -R -k 20`

Example output:

```
[+] Version 0.1.20210328
[+] Setting mode BSGS
[+] Min range: 800000000000000000000000000000
[+] Max range: ffffffffffffffffffffffffffffff
[+] Setting random mode.
[+] Setting k factor to 20
[+] Opening file tests/120.txt
[+] Added 1 points from file
[+] Bit Range 120
[+] Setting N up to 17592253153280.
[+] Init 1st bloom filter for 83886080 elements : 287.00 MB
[+] Init 2nd bloom filter for 4194304 elements : 14.00 MB
[+] Allocating 6.0 MB for 209716 aMP Points
[+] Precalculating 209716 aMP points
[+] Allocating 64.00 MB for 4194304 bP Points
[+] processing 83886080/83886080 bP points : 100 %
[+] Sorting 83886080 elements
[+] Thread 0: 0000000000000000000000000000000000e6389dbe5f63a094d7fcc748e2ccba
Total 703690126131200 keys in 30 seconds: 23456337537706 keys/s
(Thread output omited....)
```

**23 Terakeys/s for one single thread**

Want to more Speed use a bigger -k value like 128, it will use some 2.5 GB of RAM


```
[+] Version 0.1.20210328
[+] Setting mode BSGS
[+] Min range: 800000000000000000000000000000
[+] Max range: ffffffffffffffffffffffffffffff
[+] Setting random mode.
[+] Setting k factor to 128
[+] Opening file tests/120.txt
[+] Added 1 points from file
[+] Bit Range 120
[+] Setting N up to 17592186044416.
[+] Init 1st bloom filter for 536870912 elements : 1840.00 MB
[+] Init 2nd bloom filter for 26843546 elements : 92.00 MB
[+] Allocating 1.0 MB for 32768 aMP Points
[+] Precalculating 32768 aMP points
[+] Allocating 409.00 MB for 26843546 bP Points
[+] processing 536870912/536870912 bP points : 100 %
[+] Sorting 26843546 elements
[+] Thread 0: 000000000000000000000000000000000086a2afb9eac0a5ea30e7a554a88aec
(Thread output omited....)
Total 4679521487814656 keys in 30 seconds: 155984049593821 keys/s
```

**~155 Terakeys/s for one single thread**

OK at this point maybe you want to use ALL your RAM memory to solve the puzzle 120, just a bigger -k value

I already tested it with some **24 GB **used with `-k 1024` and I get **1.16 Petakeys/s per thread.**

with 6 threads

`./keyhunt -m bsgs -f tests/120.txt -b 120 -R -k 1024 -q -p ./bPfile.bin -t 6`

Output:

```
[+] Version 0.1.20210328
[+] Setting mode BSGS
[+] Min range: 800000000000000000000000000000
[+] Max range: ffffffffffffffffffffffffffffff
[+] Setting random mode.
[+] Setting k factor to 1024
[+] Set quiet thread output
[+] Setting 6 threads
[+] Opening file tests/120.txt
[+] Added 1 points from file
[+] Bit Range 120
[+] Setting N up to 17592186044416.
[+] Init 1st bloom filter for 4294967296 elements : 14722.00 MB
[+] Init 2nd bloom filter for 214748365 elements : 736.00 MB
[+] Allocating 0.0 MB for 4096 aMP Points
[+] Precalculating 4096 aMP points
[+] Allocating 3276.00 MB for 214748365 bP Points
[+] Reading 4294967296 bP points from file ./bPfile.bin
[+] processing 4294967296/4294967296 bP points : 100 %
[+] Sorting 214748365 elements
Total 157238958864990208 keys in 30 seconds: 5241298628833006 keys/s
```
I get 5.2 Petakeys/s total

## FAQ

- Where the privatekeys will be saved?
R: In a file called `KEYFOUNDKEYFOUND.txt`

- Is available for Windows?
R: It can be compiled with mingw, It can be executed in the Ubuntu shell for windows 10

## Dependencies
- pthread

Tested under Debian, Termux, Ubuntu Shell for windows 10

## Donation

- BTC: 1Coffee1jV4gB5gaXfHgSHDz9xx9QSECVW
- ETH: 0x6222978c984C22d21b11b5b6b0Dd839C75821069
- DOGE: DKAG4g2HwVFCLzs7YWdgtcsK6v5jym1ErV
- BCB: bcb_3rf4pzhrdeziygir8t5pmep4xdwqwyk1xgmytzyo991gdez1sgq1ehb3a8jh
