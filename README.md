2wif is a Python 3 script which takes either a plaintext or
a binary file and generates corresponding public and private 
keypair, and (compressed) WIF, for which can be used in
various cryptocurrency blockchains.
Bitcoin and Litecoin are currently supported


usage: timestamper.py [-h] -f FILE [-p] [-e ENCODING] [-uw] -c COIN

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  A file to be used as the secret exponent
  -p, --plaintext-file  The input file is a plaintext file.
  -e ENCODING, --encoding ENCODING
                        Character encoding used in the plaintext file, e.g.
                        utf-8
  -uw, --ucompressed-wif
                        Produce an ucompressed wif bytecode string.
  -c COIN, --coin COIN  Coin to be used. BTC, LTC or NMC. BTC is the default
                        value
