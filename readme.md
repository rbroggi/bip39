# custom bip39 

This cli allows you to generate your own [bip39](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt) 
list for even more protection when backing up your key. 

You can generate a list of 2048 words of your own instead of leveraging the public version, this way even if your key backup 
is discovered, it would still be not useful without your private mapping. 

Once you generate the mapping, store it encrypted in multiple locations. 

## Build
```shell
$ cargo build
```

## Run

Notice that you can replace the file in this repo source-code `words.txt` with whatever other text dictionary where each line
is a word.

### Generate your customized bip39 file

#### Create a customized bip39 encrypted file (recommended)
```shell
$ ./target/debug/bip39 generate -i words.txt -e -o out.bin 
```
#### Create a customized bip39 not encrypted
```shell
$ ./target/debug/bip39 generate -i words.txt -o out.txt
```
#### Create a customized bip39 into stdout
```shell
$ ./target/debug/bip39 generate -i words.txt 
```

### Decrypt your encrypted file
```shell
$ ./target/debug/bip39 decrypt -i out.bin
```
into file:
```shell
$ ./target/debug/bip39 decrypt -i out.bin -o my-bip39.txt
```

### Algorithm

The encrypted file is the result of a aes_256_cbc encryption and an IV appended to the ciphertext.

The key used to encrypt use [argon2](https://en.wikipedia.org/wiki/Argon2) is used to derive the encryption key from a user-input password.
The salt used for key-derivation is a sha256 hash of the password bytes.
