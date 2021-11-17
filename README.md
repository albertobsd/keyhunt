# keyhunt

Tool for hunt privatekeys for crypto currencies that use secp256k1  elliptic curve

Post: https://bitcointalk.org/index.php?topic=5322040.0

Work for Bitcoin
- address compress or uncompress
- hashes rmd160 compress or uncompress
- publickeys compress or uncompress

Work for Ethereum
- address

## Free Code

This code is free of charge, see the licence for more details. https://github.com/albertobsd/keyhunt/blob/main/LICENSE

This is a hobby for me but is still a lot of work.
https://github.com/albertobsd/keyhunt#donations


## For regulars users

Please read the CHANGELOG.md to see the new changes

# Download

To clone the repository:

```
git clone https://github.com/albertobsd/keyhunt.git
```

don't forget change to the keyhunt directory

`cd keyhunt`

# How to build

First compile:

```
make
```

and then execute with `-h` to see the help

```
./keyhunt -h
```


## ¡Beta!

This version is still a **beta** version, there are a lot of things that can be fail. And absoluly there are some bugs 

# Modes

Keyhunt can work in diferent ways at different speeds.

The current availables modes are:
- address
- rmd160
- xpoint
- bsgs

## Experimental modes

- minikeys
- pub2rmd

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
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Mode address
[+] Matrix screen
[+] Opening file tests/1to32.txt
[+] Setting search for btc adddress
[+] Allocating memory for 32 elements: 0.00 MB
[+] Bloom filter for 32 elements.
[+] Loading data to the bloomfilter total: 0.00 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 32 values were loaded and sorted
Base key: 1
HIT!! PrivKey: 1
pubkey: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
HIT!! PrivKey: 3
pubkey: 02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
address: 1CUNEBjYrCn2y1SdiUMohaKUi4wpP326Lb
HIT!! PrivKey: 7
pubkey: 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc
address: 19ZewH8Kk1PDbSNdJ97FP4EiCjTRaZMZQA
HIT!! PrivKey: 8
pubkey: 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01
address: 1EhqbyUMvvs7BfL8goY6qcPbD6YKfPqb7e
(Output omitted)
```

In this mode you can specify to seach only address compressed or uncompressed with `-l compress` or  `-l uncompress`

Test your luck with the random parameter `-R` againts the puzzle #64

```
./keyhunt -m address -f tests/64.txt -b 64 -l compress -R -q -s 10
```

Please note the change from `-r 1:FFFFFFFF` to `-b 64`, with -b you can specify the bit range

output:
```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Mode address
[+] Search compress only
[+] Random mode
[+] Quiet thread output
[+] Stats output every 10 seconds
[+] Opening file tests/64.txt
[+] Setting search for btc adddress
[+] Allocating memory for 1 elements: 0.00 MB
[+] Bloom filter for 1 elements.
[+] Loading data to the bloomfilter total: 0.00 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 1 values were loaded and sorted
[+] Total 6291456 keys in 20 seconds: 314572 keys/s
```

### vanity search.

well this function always be there in the code but is not eficient, use only as a test and for fun, anyway if you want to search for a *vanity* address for you, you also *need* to search for some address at the same time this last is not optional, please feel free of use the VanitySearch
 from Jean Luc Pons (https://github.com/JeanLucPons/VanitySearch) if you want a better speed.
 
Try to find all the unsolved puzzles at the same time while you search for a cool address for yourself.

Unsolved puzzles:

```
16jY7qLJnxb7CHZyqBP8qca9d51gAjyXQN
13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so
1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9
1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ
19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG
1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU
1JTK7s9YVYywfm5XUH7RNhHJH1LshCaRFR
12VVRNPi4SJqUTsp6FmqDqY5sGosDtysn4
1FWGcVDK3JGzCC3WtkYetULPszMaK2Jksv
1DJh2eHFYQfACPmrvpyWc8MSTYKh7w9eRF
1Bxk4CQdqL9p22JEtDfdXMsng1XacifUtE
15qF6X51huDjqTmF9BJgxXdt1xcj46Jmhb
1ARk8HWJMn8js8tQmGUJeQHjSE7KRkn2t8
15qsCm78whspNQFydGJQk5rexzxTQopnHZ
13zYrYhhJxp6Ui1VV7pqa5WDhNWM45ARAC
14MdEb4eFcT3MVG5sPFG4jGLuHJSnt1Dk2
1CMq3SvFcVEcpLMuuH8PUcNiqsK1oicG2D
1K3x5L6G57Y494fDqBfrojD28UJv4s5JcK
1PxH3K1Shdjb7gSEoTX7UPDZ6SH4qGPrvq
16AbnZjZZipwHMkYKBSfswGWKDmXHjEpSf
19QciEHbGVNY4hrhfKXmcBBCrJSBZ6TaVt
1EzVHtmbN4fs4MiNk3ppEnKKhsmXYJ4s74
1AE8NzzgKE7Yhz7BWtAcAAxiFMbPo82NB5
17Q7tuG2JwFFU9rXVj3uZqRtioH3mx2Jad
1K6xGMUbs6ZTXBnhw1pippqwK6wjBWtNpL
15ANYzzCp5BFHcCnVFzXqyibpzgPLWaD8b
18ywPwj39nGjqBrQJSzZVq2izR12MDpDr8
1CaBVPrwUxbQYYswu32w7Mj4HR4maNoJSX
1JWnE6p6UN7ZJBN7TtcbNDoRcjFtuDWoNL
1CKCVdbDJasYmhswB6HKZHEAnNaDpK7W4n
1PXv28YxmYMaB8zxrKeZBW8dt2HK7RkRPX
1AcAmB6jmtU6AiEcXkmiNE9TNVPsj9DULf
1EQJvpsmhazYCcKX5Au6AZmZKRnzarMVZu
18KsfuHuzQaBTNLASyj15hy4LuqPUo1FNB
15EJFC5ZTs9nhsdvSUeBXjLAuYq3SWaxTc
1HB1iKUqeffnVsvQsbpC6dNi1XKbyNuqao
1GvgAXVCbA8FBjXfWiAms4ytFeJcKsoyhL
1824ZJQ7nKJ9QFTRBqn7z7dHV5EGpzUpH3
18A7NA9FTsnJxWgkoFfPAFbQzuQxpRtCos
1NeGn21dUDDeqFQ63xb2SpgUuXuBLA4WT4
174SNxfqpdMGYy5YQcfLbSTK3MRNZEePoy
1MnJ6hdhvK37VLmqcdEwqC3iFxyWH2PHUV
1KNRfGWw7Q9Rmwsc6NT5zsdvEb9M2Wkj5Z
1PJZPzvGX19a7twf5HyD2VvNiPdHLzm9F6
1GuBBhf61rnvRe4K8zu8vdQB3kHzwFqSy7
17s2b9ksz5y7abUm92cHwG8jEPCzK3dLnT
1GDSuiThEV64c166LUFC9uDcVdGjqkxKyh
1Me3ASYt5JCTAK2XaC32RMeH34PdprrfDx
1CdufMQL892A69KXgv6UNBD17ywWqYpKut
1BkkGsX9ZM6iwL3zbqs7HWBV7SvosR6m8N
1PXAyUB8ZoH3WD8n5zoAthYjN15yN5CVq5
1AWCLZAjKbV1P7AHvaPNCKiB7ZWVDMxFiz
1G6EFyBRU86sThN3SSt3GrHu1sA7w7nzi4
1MZ2L1gFrCtkkn6DnTT2e4PFUTHw9gNwaj
1Hz3uv3nNZzBVMXLGadCucgjiCs5W9vaGz
1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua
16zRPnT8znwq42q7XeMkZUhb1bKqgRogyy
1KrU4dHE5WrW8rhWDsTRjR21r8t3dsrS3R
17uDfp5r4n441xkgLFmhNoSW1KWp6xVLD
13A3JrvXmvg5w9XGvyyR4JEJqiLz8ZySY3
16RGFo6hjq9ym6Pj7N5H7L1NR1rVPJyw2v
1UDHPdovvR985NrWSkdWQDEQ1xuRiTALq
15nf31J46iLuK1ZkTnqHo7WgN5cARFK3RA
1Ab4vzG6wEQBDNQM1B2bvUz4fqXXdFk2WT
1Fz63c775VV9fNyj25d9Xfw3YHE6sKCxbt
1QKBaU6WAeycb3DbKbLBkX7vJiaS8r42Xo
1CD91Vm97mLQvXhrnoMChhJx4TP9MaQkJo
15MnK2jXPqTMURX4xC3h4mAZxyCcaWWEDD
13N66gCzWWHEZBxhVxG18P8wyjEWF9Yoi1
1NevxKDYuDcCh1ZMMi6ftmWwGrZKC6j7Ux
19GpszRNUej5yYqxXoLnbZWKew3KdVLkXg
1M7ipcdYHey2Y5RZM34MBbpugghmjaV89P
18aNhurEAJsw6BAgtANpexk5ob1aGTwSeL
1FwZXt6EpRT7Fkndzv6K4b4DFoT4trbMrV
1CXvTzR6qv8wJ7eprzUKeWxyGcHwDYP1i2
1MUJSJYtGPVGkBCTqGspnxyHahpt5Te8jy
13Q84TNNvgcL3HJiqQPvyBb9m4hxjS3jkV
1LuUHyrQr8PKSvbcY1v1PiuGuqFjWpDumN
18192XpzzdDi2K11QVHR7td2HcPS6Qs5vg
1NgVmsCCJaKLzGyKLFJfVequnFW9ZvnMLN
1AoeP37TmHdFh8uN72fu9AqgtLrUwcv2wJ
1FTpAbQa4h8trvhQXjXnmNhqdiGBd1oraE
14JHoRAdmJg3XR4RjMDh6Wed6ft6hzbQe9
19z6waranEf8CcP8FqNgdwUe1QRxvUNKBG
14u4nA5sugaswb6SZgn5av2vuChdMnD9E5
1NBC8uXJy1GiJ6drkiZa1WuKn51ps7EPTv
```

To search only one vanity address is with  `-v 1Hunter1` where `1Good1` is the vanity addres that are you looking for:

full command
```
./keyhunt -m address -f tests/unsolvedpuzzles.txt -l compress -R -b 256 -v 1Good
```

output:

```
[+] Version 0.2.211012 Chocolate ¡Beta!, developed by AlbertoBSD
[+] Mode address
[+] Search compress only
[+] Random mode
[+] Added Vanity search : 1Good
[+] Opening file tests/unsolvedpuzzles.txt
[+] Setting search for btc adddress
[+] Allocating memory for 86 elements: 0.00 MB
[+] Bloom filter for 86 elements.
[+] Loading data to the bloomfilter total: 0.00 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 86 values were loaded and sorted
Base key: bc850706b582fe5dba5c4e10b62af4872bfbf87018986f4bXXXXXXXXXXXXXXXX
Vanity privKey: bc850706b582fe5dba5c4e10b62af4872bfbf87018986f4bXXXXXXXXXXXXXXXX
Address compressed: 1Goodj7J2nYETeiYM3uxRvekfC3VkpsCfM
```

challenge your self and use keythunt and find the privatekeys for this address `1Goodj7J2nYETeiYM3uxRvekfC3VkpsCfM`

publickey:

```
03dd178097fef876f59f6f5d3c384bab8e824f116c864cd552edbf420a8e157d88
```

command to search multiple vanity address from a file `-V filename.txt` please note that it is  `-V` Capital V for read a file.

```
./keyhunt -m address -f tests/unsolvedpuzzles.txt -l compress -R -b 256 -V tests/vanitytargets.txt
```

Output:
```
[+] Version 0.2.211012 Chocolate ¡Beta!, developed by AlbertoBSD
[+] Mode address
[+] Search compress only
[+] Random mode
[+] Added Vanity file : tests/vanitytargets.txt
[D] Added Vanity search : 1GoodBoy
[D] Added Vanity search : 1BadBoy
[+] Opening file tests/unsolvedpuzzles.txt
[+] Setting search for btc adddress
[+] Allocating memory for 86 elements: 0.00 MB
[+] Bloom filter for 86 elements.
[+] Loading data to the bloomfilter total: 0.00 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 86 values were loaded and sorted
Base key: c0a082112714d9f4dba8bf07adb9bc2204c594b5c24270b0cb9a8ff6c2adc9c3
```

All the vanity address and his privatekeys will be saved in the file `vanitykeys.txt` of your current directory


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

```
./keyhunt -m rmd160 -f tests/1to32.rmd -r 1:FFFFFFFF -l compress
```

output:

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Mode rmd160
[+] Search compress only
[+] Opening file tests/1to32.rmd
[+] Allocating memory for 32 elements: 0.00 MB
[+] Bloom filter for 32 elements.
[+] Loading data to the bloomfilter total: 0.00 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 32 values were loaded and sorted
HIT!! PrivKey: 1
pubkey: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
HIT!! PrivKey: 3
pubkey: 02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
HIT!! PrivKey: 7
pubkey: 025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc
HIT!! PrivKey: 8
pubkey: 022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01
HIT!! PrivKey: 15
pubkey: 02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5
HIT!! PrivKey: 31
pubkey: 03f2dac991cc4ce4b9ea44887e5c7c0bce58c80074ab9d4dbaeb28531b7739f530
```

test your luck with the next file for th puzzle #64


```
./keyhunt -m rmd160 -f tests/64.rmd -b 64 -l compress -R -q
```

Output:

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Mode rmd160
[+] Search compress only
[+] Random mode
[+] Quiet thread output
[+] Opening file tests/64.rmd
[+] Allocating memory for 1 elements: 0.00 MB
[+] Bloom filter for 1 elements.
[+] Loading data to the bloomfilter total: 0.00 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 1 values were loaded and sorted
[+] Total 34603008 keys in 30 seconds: ~1 Mkeys/s (1153433 keys/s)
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

```./keyhunt -m xpoint -f tests/substracted40.txt -n 65536 -t 4 -b 40```

Output:

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Mode xpoint
[+] Threads : 4
[+] Quiet thread output
[+] Opening file tests/substracted40.txt
[+] Allocating memory for 6003 elements: 0.11 MB
[+] Bloom filter for 6003 elements.
[+] Loading data to the bloomfilter total: 0.02 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 6003 values were loaded and sorted
HIT!! PrivKey: 800258a2ce
pubkey: 0274241b684e7c31e7933510b510aa14de9ac88ec3635bdd35a3bcf1d16da210be
HIT!! PrivKey: 8009c16fb9
pubkey: 027c3463c3d4e034f328749e2ac17b47a24b42ad47aaab0ec09d4d0abeee3ab46d

```

After the hit we need to search the substracted index and make a simple math operation to get the real privatek:

```
0274241b684e7c31e7933510b510aa14de9ac88ec3635bdd35a3bcf1d16da210be # + 453856235784
```
The Operation is `800258a2ce` hex (+/-) in this case + `453856235784` decimal equals to `E9AE4933D6`

This is an easy example, I been trying the puzzle 120 with more than 500 millions of substracted keys and no luck.

Test you luck with the puzzle 120 with xpoint:

```./keyhunt -m xpoint -f tests/120.txt -t 4 -b 120 -R -q```

Output:

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Mode xpoint
[+] Threads : 4
[+] Random mode
[+] Quiet thread output
[+] Opening file tests/120.txt
[+] Allocating memory for 1 elements: 0.00 MB
[+] Bloom filter for 1 elements.
[+] Loading data to the bloomfilter total: 0.00 MB
[+] Bloomfilter completed
[+] Total 544210944 keys in 30 seconds: ~18 Mkeys/s (18140364 keys/s)
```


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

```./keyhunt -m pub2rmd -f tests/puzzleswopublickey.txt -t 6 -q```

Output:

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Mode pub2rmd
[+] Threads : 6
[+] Quiet thread output
[+] Opening file tests/puzzleswopublickey.txt
[+] Allocating memory for 29 elements: 0.00 MB
[+] Bloom filter for 29 elements.
[+] Loading data to the bloomfilter total: 0.00 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 29 values were loaded and sorted
[+] Total 207618048 keys in 60 seconds: ~3 Mkeys/s (3460300 keys/s)
```

You can let it run for a while together with others scripts, if you get one of those publickeys now you can target it with a better method like bsgs or another tools like kangaroo


## bsgs mode (baby step giant step)

Keyhunt implement the BSGS algorithm to search privatekeys for a knowed publickey.

The input file need to have a list of publickeys compress or uncompress those publickey can be mixed in the same file, one publickey per line and any other word followed by an space is ignored example of the file:

```
043ffa1cc011a8d23dec502c7656fb3f93dbe4c61f91fd443ba444b4ec2dd8e6f0406c36edf3d8a0dfaa7b8f309b8f1276a5c04131762c23594f130a023742bdde # 0000000000000000000000000000000000800000000000000000100000000000
046534b9e9d56624f5850198f6ac462f482fec8a60262728ee79a91cac1d60f8d6a92d5131a20f78e26726a63d212158b20b14c3025ebb9968c890c4bab90bfc69 # 0000000000000000000000000000000000800000000000000000200000000000
```

This example contains 2 publickeys followed by his privatekey just to test the correct behavior of the application.

*Don't load more than 100 or 1000 publickeys* if you lad more than it will take a long long time in update the speed counter and the speed will be very low.

btw any word followed by and space after the publickey is ignored the file can be only the publickeys:

```
043ffa1cc011a8d23dec502c7656fb3f93dbe4c61f91fd443ba444b4ec2dd8e6f0406c36edf3d8a0dfaa7b8f309b8f1276a5c04131762c23594f130a023742bdde
046534b9e9d56624f5850198f6ac462f482fec8a60262728ee79a91cac1d60f8d6a92d5131a20f78e26726a63d212158b20b14c3025ebb9968c890c4bab90bfc69
```

### File creation

the bsgs mode `-m bsgs` now can create automatically the files needed to speed up the initial load process of keyhunt this is the bloom filters creation and the bp table creation.

To request to keyhunt to create those files automatically use `-S` Capital S for SAVE and READ files.
The 3 files needed for keyhunt can vary from size depending of your values of `-n` and `-k` , so make your test and stick to one combination of (n,k) values or you can end with hundreds of unnesesary files.

The 3 Files size are the same amount of memory used in runtime.

The files are created if they don't exist when you run the program the first time.

example of file creation:

```
./keyhunt -m bsgs -f tests/120.txt -R -b 120 -q -S
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Random mode
[+] Quiet thread output
[+] Mode BSGS random
[+] Opening file tests/120.txt
[+] Added 1 points from file
[+] Bit Range 120
[+] -- from : 0x800000000000000000000000000000
[+] -- to   : 0x1000000000000000000000000000000
[+] N = 0x100000000000
[+] Bloom filter for 4194304 elements : 14.00 MB
[+] Bloom filter for 209716 elements : 0.72 MB
[+] Allocating 3.00 MB for 209716 bP Points
[+] processing 4194304/4194304 bP points : 100%
[+] Sorting 209716 elements... Done!
[+] Writing bloom filter to file keyhunt_bsgs_0_4194304.blm .. Done!
[+] Writing bloom filter to file keyhunt_bsgs_1_209716.blm .. Done!
[+] Writing bP Table to file keyhunt_bsgs_2_209716.tbl .. Done!
[+] Total 439804651110400 keys in 30 seconds: ~14 Tkeys/s (14660155037013 keys/s)
[+] Total 897201488265216 keys in 60 seconds: ~14 Tkeys/s (14953358137753 keys/s)
```

when we run the program for second time the files are now readed and the bP Points processing is omited:

```
./keyhunt -m bsgs -f tests/120.txt -b 120 -q -S
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Quiet thread output
[+] Turn off stats output
[+] Mode BSGS secuential
[+] Opening file tests/120.txt
[+] Added 1 points from file
[+] Bit Range 120
[+] -- from : 0x800000000000000000000000000000
[+] -- to   : 0x1000000000000000000000000000000
[+] N = 0x100000000000
[+] Bloom filter for 4194304 elements : 14.00 MB
[+] Bloom filter for 209716 elements : 0.72 MB
[+] Allocating 3.00 MB for 209716 bP Points
[+] Reading bloom filter from file keyhunt_bsgs_0_4194304.blm .. Done!
[+] Reading bloom filter from file keyhunt_bsgs_1_209716.blm .. Done!
[+] Reading bP Table from file keyhunt_bsgs_2_209716.tbl ..Done!
^C
```

All the next examples were made with the `-S` option I just ommit that part of the output to avoid confutions use `-S` if you want, but remember with a great `-n` there must also come great files

### Examples

To try to find those privatekey this is the line of execution:

```
time ./keyhunt -m bsgs -f tests/test120.txt -b 120 -S
```

Output:

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Mode BSGS secuential
[+] Opening file tests/test120.txt
[+] Added 2 points from file
[+] Bit Range 120
[+] -- from : 0x800000000000000000000000000000
[+] -- to   : 0x1000000000000000000000000000000
[+] N = 0x100000000000
[+] Bloom filter for 4194304 elements : 14.00 MB
[+] Bloom filter for 209716 elements : 0.72 MB
[+] Allocating 3.00 MB for 209716 bP Points
[+] Reading bloom filter from file keyhunt_bsgs_0_4194304.blm .. Done!
[+] Reading bloom filter from file keyhunt_bsgs_1_209716.blm .. Done!
[+] Reading bP Table from file keyhunt_bsgs_2_209716.tbl ..Done!
[+] Thread Key found privkey 800000000000000000100000000000
[+] Publickey 043ffa1cc011a8d23dec502c7656fb3f93dbe4c61f91fd443ba444b4ec2dd8e6f0406c36edf3d8a0dfaa7b8f309b8f1276a5c04131762c23594f130a023742bdde
[+] Thread Key found privkey 800000000000000000200000000000
[+] Publickey 046534b9e9d56624f5850198f6ac462f482fec8a60262728ee79a91cac1d60f8d6a92d5131a20f78e26726a63d212158b20b14c3025ebb9968c890c4bab90bfc69
All points were found

real    0m3.642s
user    0m3.637s
sys     0m0.005s

```

Test the puzzle 120 with the next publickey:

```
02CEB6CBBCDBDF5EF7150682150F4CE2C6F4807B349827DCDBDD1F2EFA885A2630
```

Line of execution in random mode `-R` or -B random

```./keyhunt -m bsgs -f tests/120.txt -b 120 -q -s 10 -R```

```./keyhunt -m bsgs -f tests/120.txt -b 120 -q -s 10 -B random```


Example Output:

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Quiet thread output
[+] Stats output every 10 seconds
[+] Mode BSGS random
[+] Opening file tests/120.txt
[+] Added 1 points from file
[+] Bit Range 120
[+] -- from : 0x800000000000000000000000000000
[+] -- to   : 0x1000000000000000000000000000000
[+] N = 0x100000000000
[+] Bloom filter for 4194304 elements : 14.00 MB
[+] Bloom filter for 209716 elements : 0.72 MB
[+] Allocating 3.00 MB for 209716 bP Points
[+] processing 4194304/4194304 bP points : 100%
[+] Sorting 209716 elements... Done!
^C] Total 439804651110400 keys in 30 seconds: ~14 Tkeys/s (14660155037013 keys/s)
```

Good speed no? 14.6 Terakeys/s for one single thread

**[+] Total 439804651110400 keys in 30 seconds: ~14 Tkeys/s (14660155037013 keys/s)**

We can speed up our process selecting a bigger K value `-k value` btw the n value is the total length of item tested in the radom range, a bigger k value means more ram to be use:

Example:
```
./keyhunt -m bsgs -f tests/120.txt -b 120 -R -k 20
```

Output:

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Random mode
[+] K factor 20
[+] Mode BSGS random
[+] Opening file tests/120.txt
[+] Added 1 points from file
[+] Bit Range 120
[+] -- from : 0x800000000000000000000000000000
[+] -- to   : 0x1000000000000000000000000000000
[+] N = 0xfffff000000
[+] Bloom filter for 83886080 elements : 287.00 MB
[+] Bloom filter for 4194304 elements : 14.38 MB
[+] Allocating 64.00 MB for 4194304 bP Points
[+] processing 83886080/83886080 bP points : 100%
^C] Thread 0xc769b6007dccced55c48c28db483f3  : ~252 Tkeys/s (252740831805440 keys/s)
```

**~252 Terakeys/s for one single thread**

Note the value of N `0xfffff000000` with k = 20 this mean that the N value is less than the default value `0x100000000000` that is because k is not a 2^X number

if you want to more Speed use a bigger -k value like 128, it will use some 2.5 GB of RAM


```
./keyhunt -m bsgs -f tests/120.txt -b 120 -R -k 128
```

Output

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Random mode
[+] K factor 128
[+] Mode BSGS random
[+] Opening file tests/120.txt
[+] Added 1 points from file
[+] Bit Range 120
[+] -- from : 0x800000000000000000000000000000
[+] -- to   : 0x1000000000000000000000000000000
[+] N = 0x100000000000
[+] Bloom filter for 536870912 elements : 1840.00 MB
[+] Bloom filter for 26843546 elements : 92.02 MB
[+] processing 536870912/536870912 bP points : 100%
^C] Thread 0xa6be81c8ac15f65047f322862e37c4  s: ~1 Pkeys/s (1600302523840375 keys/s
```

**~1.6 Pkeys/s for one single thread**

OK at this point maybe you want to use ALL your RAM memory to solve the puzzle 120, just a bigger -k value

I already tested it with some **18 GB ** used with `-k 1024` and I get **~46 Petakeys/s per thread.**

with **6** threads

`./keyhunt -m bsgs -f tests/120.txt -b 120 -R -k 1024 -q -t 6`

Output:

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Random mode
[+] K factor 1024
[+] Quiet thread output
[+] Threads : 6
[+] Mode BSGS random
[+] Opening file tests/120.txt
[+] Added 1 points from file
[+] Bit Range 120
[+] -- from : 0x800000000000000000000000000000
[+] -- to   : 0x1000000000000000000000000000000
[+] N = 0x100000000000
[+] Bloom filter for 4294967296 elements : 14722.00 MB
[+] Bloom filter for 214748365 elements : 736.13 MB
[+] Allocating 3276.00 MB for 214748365 bP Points
[+] Sorting 214748365 elements
[+] Total 5607544486029688832 keys in 120 seconds: ~46 Pkeys/s (46729537383580740 keys/s)
```
I get ~46 Petakeys/s total

Warning: the default n value have a maximun K of `4096` if that value is exceed the program can have an unknow behavior or suboptimal speed.
If you want to use a bigger K I recomend use a bigger N value `-n 0x400000000000` and half your K value.

Just as comparation with the BSGS program of JLP
Same publickeys and ranged used by his sample:

publickeys:
```
0459A3BFDAD718C9D3FAC7C187F1139F0815AC5D923910D516E186AFDA28B221DC994327554CED887AAE5D211A2407CDD025CFC3779ECB9C9D7F2F1A1DDF3E9FF8
04A50FBBB20757CC0E9C41C49DD9DF261646EE7936272F3F68C740C9DA50D42BCD3E48440249D6BC78BC928AA52B1921E9690EBA823CBC7F3AF54B3707E6A73F34
0404A49211C0FE07C9F7C94695996F8826E09545375A3CF9677F2D780A3EB70DE3BD05357CAF8340CB041B1D46C5BB6B88CD9859A083B0804EF63D498B29D31DD1
040B39E3F26AF294502A5BE708BB87AEDD9F895868011E60C1D2ABFCA202CD7A4D1D18283AF49556CF33E1EA71A16B2D0E31EE7179D88BE7F6AA0A7C5498E5D97F
04837A31977A73A630C436E680915934A58B8C76EB9B57A42C3C717689BE8C0493E46726DE04352832790FD1C99D9DDC2EE8A96E50CAD4DCC3AF1BFB82D51F2494
040ECDB6359D41D2FD37628C718DDA9BE30E65801A88A00C3C5BDF36E7EE6ADBBAD71A2A535FCB54D56913E7F37D8103BA33ED6441D019D0922AC363FCC792C29A
0422DD52FCFA3A4384F0AFF199D019E481D335923D8C00BADAD42FFFC80AF8FCF038F139D652842243FC841E7C5B3E477D901F88C5AB0B88EE13D80080E413F2ED
04DB4F1B249406B8BD662F78CBA46F5E90E20FE27FC69D0FBAA2F06E6E50E536695DF83B68FD0F396BB9BFCF6D4FE312F32A43CF3FA1FE0F81DF70C877593B64E0
043BD0330D7381917F8860F1949ACBCCFDC7863422EEE2B6DB7EDD551850196687528B6D2BC0AA7A5855D168B26C6BAF9DDCD04B585D42C7B9913F60421716D37A
04332A02CA42C481EAADB7ADB97DF89033B23EA291FDA809BEA3CE5C3B73B20C49C410D1AD42A9247EB8FF217935C9E28411A08B325FBF28CC2AF8182CE2B5CE38
04513981849DE1A1327DEF34B51F5011C5070603CA22E6D868263CB7C908525F0C19EBA6BD2A8DCF651E4342512EDEACB6EA22DA323A194E25C6A1614ABD259BC0
04D4E6FA664BD75A508C0FF0ED6F2C52DA2ADD7C3F954D9C346D24318DBD2ECFC6805511F46262E10A25F252FD525AF1CBCC46016B6CD0A7705037364309198DA1
0456B468963752924DBF56112633DC57F07C512E3671A16CD7375C58469164599D1E04011D3E9004466C814B144A9BCB7E47D5BACA1B90DA0C4752603781BF5873
04D5BE7C653773CEE06A238020E953CFCD0F22BE2D045C6E5B4388A3F11B4586CBB4B177DFFD111F6A15A453009B568E95798B0227B60D8BEAC98AF671F31B0E2B
04B1985389D8AB680DEDD67BBA7CA781D1A9E6E5974AAD2E70518125BAD5783EB5355F46E927A030DB14CF8D3940C1BED7FB80624B32B349AB5A05226AF15A2228
0455B95BEF84A6045A505D015EF15E136E0A31CC2AA00FA4BCA62E5DF215EE981B3B4D6BCE33718DC6CF59F28B550648D7E8B2796AC36F25FF0C01F8BC42A16FD9
```

set range

```
-r 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e0000000000000000:49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5effffffffffffffff
```

the n value to get the same baby step table:


```
-n 1152921504606846976
```

number of threads

```
-t 6
```

Hidding the speed:

```
-s 0
```

command:

```
time ./keyhunt -m bsgs -t 6 -f tests/in.txt -r 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e0000000000000000:49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5effffffffffffffff -n 0x1000000000000000 -M -s 0
```

Output:
```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Threads : 6
[+] Matrix screen
[+] Turn off stats output
[+] Mode BSGS secuential
[+] Opening file tests/in.txt
[+] Added 16 points from file
[+] Range
[+] -- from : 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e0000000000000000
[+] -- to   : 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5effffffffffffffff
[+] N = 0x1000000000000000
[+] Bloom filter for 1073741824 elements : 3680.00 MB
[+] Bloom filter for 53687092 elements : 184.03 MB
[+] Allocating 819.00 MB for 53687092 bP Points
[+] processing 1073741824/1073741824 bP points : 100%
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e0000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e2000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e1000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e3000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e4000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e5000000000000000
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e5698aaab6cac52b3
[+] Publickey 0404a49211c0fe07c9f7c94695996f8826e09545375a3cf9677f2d780a3eb70de3bd05357caf8340cb041b1d46c5bb6b88cd9859a083b0804ef63d498b29d31dd1
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e59c839258c2ad7a0
[+] Publickey 040b39e3f26af294502a5be708bb87aedd9f895868011e60c1d2abfca202cd7a4d1d18283af49556cf33e1ea71a16b2d0e31ee7179d88be7f6aa0a7c5498e5d97f
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e38160da9ebeaecd7
[+] Publickey 04db4f1b249406b8bd662f78cba46f5e90e20fe27fc69d0fbaa2f06e6e50e536695df83b68fd0f396bb9bfcf6d4fe312f32a43cf3fa1fe0f81df70c877593b64e0
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e54cad3cfbc2a9c2b
[+] Publickey 04332a02ca42c481eaadb7adb97df89033b23ea291fda809bea3ce5c3b73b20c49c410d1ad42a9247eb8ff217935c9e28411a08b325fbf28cc2af8182ce2b5ce38
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e0d5eccc38d0230e6
[+] Publickey 04513981849de1a1327def34b51f5011c5070603ca22e6d868263cb7c908525f0c19eba6bd2a8dcf651e4342512edeacb6ea22da323a194e25c6a1614abd259bc0
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e2452dd26bc983cd5
[+] Publickey 04b1985389d8ab680dedd67bba7ca781d1a9e6e5974aad2e70518125bad5783eb5355f46e927a030db14cf8d3940c1bed7fb80624b32b349ab5a05226af15a2228
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e6000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e7000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e8000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e9000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5ea000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5eb000000000000000
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5ebb3ef3883c1866d4
[+] Publickey 0459a3bfdad718c9d3fac7c187f1139f0815ac5d923910d516e186afda28b221dc994327554ced887aae5d211a2407cdd025cfc3779ecb9c9d7f2f1a1ddf3e9ff8
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5eb5abc43bebad3207
[+] Publickey 04a50fbbb20757cc0e9c41c49dd9df261646ee7936272f3f68c740c9da50d42bcd3e48440249d6bc78bc928aa52b1921e9690eba823cbc7f3af54b3707e6a73f34
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e765fb411e63b92b9
[+] Publickey 04837a31977a73a630c436e680915934a58b8c76eb9b57a42c3c717689be8c0493e46726de04352832790fd1c99d9ddc2ee8a96e50cad4dcc3af1bfb82d51f2494
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e7d0e6081c7e0e865
[+] Publickey 040ecdb6359d41d2fd37628c718dda9be30e65801a88a00c3c5bdf36e7ee6adbbad71a2a535fcb54d56913e7f37d8103ba33ed6441d019d0922ac363fcc792c29a
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e79d808cab1decf8d
[+] Publickey 043bd0330d7381917f8860f1949acbccfdc7863422eee2b6db7edd551850196687528b6d2bc0aa7a5855d168b26c6baf9ddcd04b585d42c7b9913f60421716d37a
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e7c43b8e079ae7278
[+] Publickey 0456b468963752924dbf56112633dc57f07c512e3671a16cd7375c58469164599d1e04011d3e9004466c814b144a9bcb7e47d5baca1b90da0c4752603781bf5873
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e8d63ef128ef66b42
[+] Publickey 04d5be7c653773cee06a238020e953cfcd0f22be2d045c6e5b4388a3f11b4586cbb4b177dffd111f6a15a453009b568e95798b0227b60d8beac98af671f31b0e2b
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5e7ad38337c7f173c7
[+] Publickey 0455b95bef84a6045a505d015ef15e136e0a31cc2aa00fa4bca62e5df215ee981b3b4d6bce33718dc6cf59f28b550648d7e8b2796ac36f25ff0c01f8bc42a16fd9
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5ec000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5ed000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5ee000000000000000
[+] Thread 0x49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5ef000000000000000
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5ec737344ca673ce28
[+] Publickey 0422dd52fcfa3a4384f0aff199d019e481d335923d8c00badad42fffc80af8fcf038f139d652842243fc841e7c5b3e477d901f88c5ab0b88ee13d80080e413f2ed
[+] Thread Key found privkey 49dccfd96dc5df56487436f5a1b18c4f5d34f65ddb48cb5ee3579364de939b0c
[+] Publickey 04d4e6fa664bd75a508c0ff0ed6f2c52da2add7c3f954d9c346d24318dbd2ecfc6805511f46262e10a25f252fd525af1cbcc46016b6cd0a7705037364309198da1
All points were found

real    164m32.904s
user    973m8.387s
sys     0m26.803s
```

Amount of RAM used ~4.5 GB, time to solve the sixteen publickeys in the range of 64 bits key-space: 164 min (~2.7 hrs) using 6 threads

if we run the same command with `-n 0x1000000000000000 -k 4 -t 6` it use ~18 GB or RAM and solve the same keys in 60 minutes

```
All points were found

real    59m50.533s
user    329m29.836s
sys     0m22.752s
```

There are several variations to play with the values `-n` and `-k` but there are some minimal values required, n can not be less than 1048576 (2^20)

To get optimal performance the k values need to be base 2^x values, this is 1,2,4,8,16,32 ... 

### Valid n and k values

```
+------+----------------------+-------------+
| bits |  n in hexadecimal    | k max value |
+------+----------------------+-------------+
|   20 |             0x100000 | 1 (default) |
|   22 |             0x400000 | 2           |
|   24 |            0x1000000 | 4           |
|   26 |            0x4000000 | 8           |
|   28 |           0x10000000 | 16          |
|   30 |           0x40000000 | 32          |
|   32 |          0x100000000 | 64          |
|   34 |          0x400000000 | 128         |
|   36 |         0x1000000000 | 256         |
|   38 |         0x4000000000 | 512         |
|   40 |        0x10000000000 | 1024        |
|   42 |        0x40000000000 | 2048        |
|   44 |       0x100000000000 | 4096        |
|   46 |       0x400000000000 | 8192        |
|   48 |      0x1000000000000 | 16384       |
|   50 |      0x4000000000000 | 32768       |
|   52 |     0x10000000000000 | 65536       |
|   54 |     0x40000000000000 | 131072      |
|   56 |    0x100000000000000 | 262144      |
|   58 |    0x400000000000000 | 524288      |
|   60 |   0x1000000000000000 | 1048576     |
|   62 |   0x4000000000000000 | 2097152     |
|   64 |  0x10000000000000000 | 4194304     |
+------+----------------------+-------------+
```
 
**if you exceed the Max value of K the program can have a unknow behavior, the program can have a suboptimal performance, or in the wrong cases you can missing some hits and have an incorrect SPEED.**

Note for user that want use it with SWAP memory. IT DON'T WORK swap memory was made to small chucks of memory also is slowly.   

### What values use according to my current RAM:

2 G
-k 128

4 G
-k 256

8 GB
-k 512

16 GB
-k 1024

32 GB
-k 2048

64 GB
-n 0x100000000000 -k 4096

128 GB
-n 0x400000000000 -k 4096

256 GB
-n 0x400000000000 -k 8192

512 GB
-n 0x1000000000000 -k 8192

1 TB
-n 0x1000000000000 -k 16384

2 TB
-n 0x4000000000000 -k 16384

4 TB
-n 0x4000000000000 -k 32768

8 TB
-n 0x10000000000000 -k 32768


### Testing puzzle 63 bits

Publickey:

```
0365ec2994b8cc0a20d40dd69edfe55ca32a54bcbbaa6b0ddcff36049301a54579
```

Command
```
time ./keyhunt -m bsgs -t 6 -f tests/63.pub -n 0x1000000000000000 -M -s 0 -S -k 4 -b 63
```

output:

```
[+] Version 0.2.211007 Chocolate ¡Beta!
[+] Threads : 6
[+] Matrix screen
[+] Turn off stats output
[+] K factor 4
[+] Mode BSGS secuential
[+] Opening file tests/63.pub
[+] Added 1 points from file
[+] Bit Range 63
[+] -- from : 0x4000000000000000
[+] -- to   : 0x8000000000000000
[+] N = 0x1000000000000000
[+] Bloom filter for 4294967296 elements : 14722.00 MB
[+] Bloom filter for 214748365 elements : 736.13 MB
[+] Allocating 3276.00 MB for 214748365 bP Points
[+] Reading bloom filter from file keyhunt_bsgs_0_4294967296.blm .. Done!
[+] Reading bloom filter from file keyhunt_bsgs_1_214748365.blm .. Done!
[+] Reading bP Table from file keyhunt_bsgs_2_214748365.tbl ..Done!
[+] Thread 0x6000000000000000
[+] Thread 0x5000000000000000
[+] Thread 0x4000000000000000
[+] Thread 0x7000000000000000
[+] Thread Key found privkey 7cce5efdaccf6808
[+] Publickey 0365ec2994b8cc0a20d40dd69edfe55ca32a54bcbbaa6b0ddcff36049301a54579
All points were found

real    4m58.644s
user    7m52.332s
sys     0m11.803s

```

Please note that number of threads was setting to 6 but only 4 threads were used, this is because the range 63 bits is small for BSGS and we only need four times the current N value to fill it, to avoid this we can use a smaller N value but with some multiplier K in that way w we can achieve the same speed and also be able to launch more threads. Repeat only in case that the range was small like this.

The next command also solve the Puzzle 63 with more threads

```
time ./keyhunt -m bsgs -t 6 -f tests/63.pub -n 0x400000000000000 -M -s 0 -S -k 8 -b 63
```

```
real    4m4.719s
user    2m15.706s
sys     0m13.009s
```

## Is my speed real?

Since this is still a beta version we can have some doubt about the speed showed in the bsgs mode.

To check this  i prepare a set of test publickeys to be found at some specific time according to your speed.

With  1 Petakeys/s the publickey will be found in 2 minutes:
Privatekey: 8000000000000001aa535d3d0c0000
Publickey : 02af4535880d694d660031a161c53a6889c45d2de513454858e94739f9c790768b

With 10 Petakeys/s the publickey will be found in 2 minutes:
Privatekey: 8000000000000010a741a462780000
Publickey : 025deee1657cd5d363cff23ec1b14781e504cbb6292c273e515d73f98065131d40

With 50 Petakeys/s the publickey will be found in 2 minutes:
Privatekey: 8000000000000053444835ec580000
Publickey : 03c13e9c6e5cbe2ac06817e4d8fd0a3e836f1a121aab91bb67ef44747b25c7d791

With  1 Exakey/s the publickey will be found in 2 minutes:
Privatekey: 800000000000068155a43676e00000
Publickey : 022b6a74badcc4c3d8fab7d01ddc1854b9d8f262172789b2aa1bb7fd42cc1b2817

With  5 Exakeys/s the publickey will be found in 2 minutes
Privatekey: 8000000000002086ac351052600000
Publickey : 024cf9e44f808e7b0bbb12a57ff63e3a8407cba1816f5e31e815d33d70e4a95a7f

With 10 Exakeys/s the publickey will be found in 2 minutes
Privatekey: 800000000000410d586a20a4c00000
Publickey : 02ee0cf78d13b4aae9c8777a0f93dff7f5be3855bd2c0f85370f861c69bb5b533a

Select one publickey that fit to your current speed save it in a file `testpublickey.txt` and test it with:

```
./keyhunt -m bsgs -f testpublickey.txt -b 120 -q
```

Change the values of k, n and t


The publickeys should be found in some 2 minutes after the load of the files

Change your n or k values according to your current memory and remember not exceed the k value of each N please check the table https://github.com/albertobsd/keyhunt#valid-n-and-k-values


## minikeys Mode

This mode is some experimental.

For the moment only Minikeys of 22 characters are available

The minikey are generated from a 16 byte buffer using the base58 encode funtion using the bitcoin  string `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz` any sugestion please let me know.


Command example:

```
./keyhunt -m minikeys -f minkey_h160.txt -C SG64GZqySYwBm9KxE1wJ28 -n 0x10000
```

Output:

```
[+] Version 0.2.211117 SSE Trick or treat ¡Beta!, developed by AlbertoBSD
[+] Mode minikeys
[+] Opening file /home/albertobsd/keyhunt/minkey_h160.txt
[+] N = 0x10000
[+] Base Minikey : SG64GZqySYwBm9KxE1wJ28
[+] Allocating memory for 61560 elements: 1.17 MB
[+] Bloom filter for 61560 elements.
[+] Loading data to the bloomfilter total: 0.21 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 61560 values were loaded and sorted
[+] Base minikey: SG64GZqySYwBm9KxE3QGrg?
HIT!! Private Key: d1a4fc1f83b2f3b31dcd999acd8288ff346f7df46401596d53964e0c69d5b4d
pubkey: 048722093a2b5dd05a84c28a18b2a6601320c9eaab9db99e76b850f9574cd3d5c987bf0c9c9ed3bd0f52124a57d9ef292b529536b225b90f8760d9c67cc3aa1c32
minikey: SG64GZqySYwBm9KxE3wJ29
address: 15azScMmHvFPAQfQafrKr48E9MqRRXSnVv
^C
```

random minikeys command

```
./keyhunt -m minikeys -f ~/keyhunt/minkey_h160.txt -q -R -n 0x1000
```

```
[+] Version 0.2.211117 SSE Trick or treat ¡Beta!, developed by AlbertoBSD
[+] Mode minikeys
[+] Quiet thread output
[+] Random mode
[+] Opening file /home/albertobsd/keyhunt/minkey_h160.txt
[+] N = 0x1000
[+] Allocating memory for 61560 elements: 1.17 MB
[+] Bloom filter for 61560 elements.
[+] Loading data to the bloomfilter total: 0.21 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 61560 values were loaded and sorted
^C] Total 2296832 keys in 120 seconds: 19140 keys/s

```


# Ethereum

Finally ethereum address are supported, for ethereum there are no modes exect for address.

if you have publickeys for ethereum you can use xpoint or bsgs mode.

to test the functionality of ethereum you can use the sample file `tests/1to32.eth`

command: 

```
./keyhunt -c eth -f tests/1to32.eth -r 1:100000000 -M
```

output:

```
[+] Version 0.2.211024 Chocolate ¡Beta!, developed by AlbertoBSD
[+] Setting search for ETH adddress.
[+] Matrix screen
[+] Stride : 1
[+] Opening file tests/1to32.eth
[+] N = 0x100000000
[+] Range
[+] -- from : 0x1
[+] -- to   : 0x100000000
[+] Allocating memory for 32 elements: 0.00 MB
[+] Bloom filter for 32 elements.
[+] Loading data to the bloomfilter total: 0.00 MB
[+] Bloomfilter completed
[+] Sorting data ... done! 32 values were loaded and sorted
Base key: 1 thread 0

 Hit!!!! PrivKey: 1
address: 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf

 Hit!!!! PrivKey: 3
address: 0x6813eb9362372eef6200f3b1dbc3f819671cba69

 Hit!!!! PrivKey: 7
address: 0xd41c057fd1c78805aac12b0a94a405c0461a6fbb
....
```



## FAQ

- Where the privatekeys will be saved?
R: In a file called `KEYFOUNDKEYFOUND.txt`

- Why the speed for bsgs say 0 keys/s
R: this was asked here https://github.com/albertobsd/keyhunt/issues/69 and here https://github.com/albertobsd/keyhunt/issues/108 and also others in telegram

Please check the video that i made to answer that https://youtu.be/MVby8mYNxbI

- Is available for Windows?
R: It can be compiled with mingw, also it can be executed in the Ubuntu shell for windows 10

Updated: 
Yes thanks to @kanhavishva
Available in: https://github.com/kanhavishva/keyhunt

Also, thanks to @WanderingPhilosopher
Available in: https://github.com/WanderingPhilosopher/keyhunt

Also thanks to @XopMC
Available in: https://github.com/XopMC/keyhunt-win


## Dependencies
- pthread
Tested under Debian and WSL Ubuntu Shell for windows 10

## Thanks

This program was possible thanks to 
- IceLand
- kanhavishva
- JLP for part of his code
- All the group of CryptoHunters that made this program possible
- All the users that tested it, report bugs, requested improvements and shared his knowledge.

## Donations

- BTC: 1Coffee1jV4gB5gaXfHgSHDz9xx9QSECVW
- ETH: 0x6222978c984C22d21b11b5b6b0Dd839C75821069
- DOGE: DKAG4g2HwVFCLzs7YWdgtcsK6v5jym1ErV


All the donations will be use only for two things:

- Native Windows version with 0 external dependencies.
- Get an affordable desktop computer with decent GPU, not highend, just to start the GPU version.

All the donators will have first access to the privates versions of keyhunt, direct support, custom scripts and quick bug fixes.