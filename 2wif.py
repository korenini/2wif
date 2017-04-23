# -*- coding: utf-8 -*-

"""
2wif is a Python 3 script which takes either a plaintext or
a binary file and generates corresponding public and private 
keypair, and (compressed) WIF, for which can be used in
various cryptocurrency blockchains.
Bitcoin and Litecoin are currently supported

author: Bojan Korenini
date: 2017-03-28

Based on:
https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
https://en.bitcoin.it/wiki/Secp256k1
https://en.bitcoin.it/wiki/Wallet_import_format
https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
https://bitcointalk.org/index.php?topic=84238.0
"""


import binascii, ecdsa, hashlib
import sys, argparse



code_str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


coins = ["BTC", "LTC", "NMC"]

encodings = ["utf-8", "utf8", "iso-8859-1", "iso8859-1", "iso-8859-2", 
             "iso8859-2", "windows-1250", "windows-1251"]



def main(**kwargs):
    
    # Select a blockchain
    if kwargs["coin"].upper() == "BTC":
    # Bitcoin
        network_version = '00'
        priv_key_prefix = '80'
    elif kwargs["coin"].upper() == "LTC":
        # Litecoin
        network_version = '30'
        priv_key_prefix = 'b0'
    else:
        print("Something went terribly wrong!")
        sys.exit(1)
    
    # Import file which is used to calculate the secret exponent
    if kwargs["plaintext"]:
        # Import a plaintext file if it exists
        try:
            with open(kwargs["file"], mode='r') as file:
                file_content_tmp = file.read()
                file_content = bytes(file_content_tmp, kwargs["encoding"].lower())
        except FileNotFoundError:
            print("Plaintext file %s doesn't exist." % kwargs["file"])
            sys.exit(1)
    else:
        # Import a binary file if it exists
        try:
            with open(kwargs["file"], mode='rb') as file:
                file_content = file.read()
        except FileNotFoundError:
            print("Binary file %s doesn't exist." % kwargs["file"])
            sys.exit(1)
            
    # Compressed or uncompressed WIF (Wallet Import Format)
    if kwargs["ucwif"]:
        wif_pad = "01"
    else:
        wif_pad = ""
    
    # SHA256
    sha = hashlib.sha256(file_content).hexdigest()

    
    wif = sha256towif(sha, priv_key_prefix, wif_pad)
    
    #
    pubkey, addr = address(sha, network_version, kwargs["ucwif"])
    
    print("")
    print("The following data coresspond to the input file %s:" % kwargs["file"])
    print("-----------------------------------------------------------")
    print("SHA256:      %s" % sha)
    print("WIF:         %s" % wif)
    print("%s address: %s" % (kwargs["coin"].upper(), addr))



def base58encode(int_value):
    encoded_lst = []
    while int_value > 0:
        int_value, mod = divmod(int_value, 58)
        encoded_lst.insert(0, code_str[mod])
    encoded_str = "".join(encoded_lst)
    return(encoded_str)



def sha256towif(sha, pkpx, com):
    """
    Takes SHA256 hash of the input file as an argument.
    Returns (compressed) WIF private key which can be imported into a wallet.
    """
    ext_sha = pkpx+sha+com
    round1 = hashlib.sha256(binascii.unhexlify(ext_sha)).hexdigest()
    round2 = hashlib.sha256(binascii.unhexlify(round1)).hexdigest()
    round1_prep = int(ext_sha + round2[:8] , 16)
    wif = base58encode(round1_prep)
    return(wif)



def address(pk, network_version, ucwif):
    pk = int(pk, 16)
    #
    pko=ecdsa.SigningKey.from_secret_exponent(pk,ecdsa.SECP256k1)
    pubkey=binascii.hexlify(pko.get_verifying_key().to_string())
    pubkey_a = pubkey[0:64]
    pubkey_b = pubkey[-1]
    #
    if ucwif:
        if (int(pubkey_b) % 2) == 0:
            pubkey2=hashlib.sha256(binascii.unhexlify(b'02'+pubkey_a)).hexdigest()
        else:
            pubkey2=hashlib.sha256(binascii.unhexlify(b'03'+pubkey_a)).hexdigest()
    else:
        pubkey2=hashlib.sha256(binascii.unhexlify(b'04'+pubkey)).hexdigest()
    #
    pubkey3=hashlib.new('ripemd160',binascii.unhexlify(pubkey2)).hexdigest()
    pubkey4=hashlib.sha256(binascii.unhexlify(network_version+pubkey3)).hexdigest()
    pubkey5=hashlib.sha256(binascii.unhexlify(pubkey4)).hexdigest()
    pubkey6=network_version+pubkey3+pubkey5[:8]
    pubnum=int(pubkey6, 16)
    address = base58encode(pubnum)
    if network_version == '00':
        address = '1'+address
    else:
        pass
    return(pubkey, address)



if __name__ == "__main__":
    
    # Check Python version. Must be Python 3!
    if (sys.version_info > (3, 0)):
        pass
    else:
        print("Please use Python version 3 to run this program.")
        sys.exit(1)

    parser = argparse.ArgumentParser()

    parser.add_argument('-f', '--file', dest="file", type=str, 
                        help='A file to be used as the secret exponent', 
                        required=True)
    parser.add_argument('-p', '--plaintext-file', dest="plaintext",
                        help="The input file is a plaintext file.", 
                        action="store_true", required=False)
    parser.add_argument('-e', '--encoding', dest="encoding", type=str,
                        help="""Character encoding used in the 
                                 plaintext file, e.g. utf-8""", 
                        required=False)
    parser.add_argument('-uw', '--ucompressed-wif', dest="ucwif",
                        help="Produce an ucompressed wif bytecode string.", 
                        action="store_true", required=False)
    parser.add_argument('-c', '--coin', dest="coin", type=str,
                        help="""Coin to be used. BTC, LTC or NMC. 
                                BTC is the default value""",
                        required=True)

    parser.set_defaults(plaintext=False, encoding=None, ucwif=False, coin="BTC")
    

    parsed = vars(parser.parse_args())
    
    
    errors = []
        

    if parsed["plaintext"] and parsed["encoding"] is None:
        errors.append("Character encoding must be profided, e.g. utf-8")
    else:
        pass
    

    if parsed["encoding"] is not None and parsed["plaintext"] == False:
        errors.append("""Character encoding is used only 
                         in combination with plaintext files.""")
    else:
        pass
    

    if parsed["encoding"] is not None:
        if parsed["encoding"].lower() in encodings:
            pass
        else:
            enc = ""
            for pos, i in enumerate(encodings):
                if pos < (len(encodings)-1):
                    enc += i + ", "
                else:
                    enc += i + "."
            errors.append("Valid character encoding strings are: %s" % enc)
    else:
        pass
    

    if parsed["coin"].upper() in coins:
        pass
    else:
        cn = ""
        for pos, i in enumerate(coins):
            if pos < (len(coins)-1):
                cn += i + ", "
            else:
                cn += i + "."
        errors.append("Only the following coins are currently supported: %s" % cn)
    

    if errors:
        errors.append("Use --help to for help with command line arguments.")
        for err in errors:
            print(err)
        sys.exit(1)
    else:
        pass
    
    main(**parsed)

