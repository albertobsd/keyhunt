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

# Dependencies
- libgmp
- pthread

Tested under Debian
