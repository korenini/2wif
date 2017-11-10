2wif may be used to create a Bitcoin, Litecoin, etc. WIF (Wallet Import Format) encoded private key from either plaintext or binary file. The resulting private/public ECDSA keypair may be imported into a crypto wallet, such as Bitcoin or Litecoin wallet. In this way, it can be used to cryptographically sign messages which can be later verified by anyone using a corresponding crypto wallet. When a cryptocurrency transaction is made to the resulting Bitcoin or Litecoin (...) public address, this transaction may serve as proof that either plaintext or a binary file from which the keypair has been generated existed before this transaction.

usage: python3 2wif.py [-h] -f FILE [-p] [-e ENCODING] [-uw] -c COIN

optional arguments:
  -h, --help
                        Show this help message and exit
  -f FILE, --file FILE
                        A file to be used as the secret exponent
  -p, --plaintext-file
                        The input file is a plaintext file.
  -e ENCODING, --encoding ENCODING
                        Character encoding used in the plaintext file, e.g. utf-8
  -uw, --uncompressed-wif
                        Produce an uncompressed WIF bytecode string.
  -c COIN, --coin COIN  Coin to be used. BTC, LTC or NMC. BTC is the default
                        value

I created this script for purposes of my lecture on blockchain technology,
at Faculty of Social Sciences, Ljubljana, Slovenia, on 24.4. 2017.
At that time confirmation Bitcoin transaction was very slow therefore I opted to use Litecoin.
Because I was unable to find an existing software that would take a binary file as an input I created my own.



