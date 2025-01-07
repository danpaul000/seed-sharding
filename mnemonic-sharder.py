import ssss
import argparse
import ctypes

def mnemonic_to_bytestring(word_list, mnemonic):
    bytestring = 0
    for word in mnemonic:
        try:
            mnemonic_idx = word_list.index(word)
        except ValueError:
            raise Exception(f"{word} not found in the list")
        bytestring = (bytestring << 11) + mnemonic_idx
    return bytestring

def bytestring_to_mnemonic(word_list, s):
    mnemonic = []
    while s > 0:
        idx = s & 0b11111111111
        mnemonic.insert(0, word_list[idx])  # Don't append or word list will come out reversed
        s = s >> 11
    return mnemonic

def condense_mnemonic(m):
    d = "english.txt"
    with open(d, "r", encoding="utf-8") as f:
        bip39_wordlist = [w.strip() for w in f.readlines()]
    return mnemonic_to_bytestring(bip39_wordlist, m.split())

def condense_mnemonics_to_shares(mnemonic_shares):
    d = "english.txt"
    with open(d, "r", encoding="utf-8") as f:
        bip39_wordlist = [w.strip() for w in f.readlines()]
    return [(index, mnemonic_to_bytestring(bip39_wordlist, mnemonic.split())) for index, mnemonic in mnemonic_shares]

# Expand a list of shares to mnemonics.  Expects a list of tuples (share_index, share_contents)
def expand_shares_to_mnemonics(shares):
    d = "english.txt"
    with open(d, "r", encoding="utf-8") as f:
        bip39_wordlist = [w.strip() for w in f.readlines()]

    mnemonic_shares = []
    for share_index, share_contents in shares:
        mnemonic = bytestring_to_mnemonic(bip39_wordlist, int(share_contents, 16))
        mnemonic_shares.append((share_index, mnemonic))
    return mnemonic_shares

# Expand a hex string to a BIP39 mnemonic.  Expects a single hex string.
def expand_string_to_mnemonic(s):
    d = "english.txt"
    with open(d, "r", encoding="utf-8") as f:
        bip39_wordlist = [w.strip() for w in f.readlines()]

    return bytestring_to_mnemonic(bip39_wordlist, int(s, 16))

def ssss_split(secret, ssss_num_shares, ssss_threshold_shares, verbose=False):
    _ssss = ctypes.CDLL('./libssss.so')
    # Set up function arg types
    _ssss.split_with_args.argtypes = [
        ctypes.c_char_p,     # secret
        ctypes.c_int,        # threshold
        ctypes.c_int,        # num_shares
        ctypes.c_int,        # use_hex
        ctypes.c_char_p,     # token
        ctypes.c_int,        # quiet
        ctypes.POINTER(ctypes.c_int), # num_output_shares
        ctypes.c_int,        # security_bits
        ctypes.c_int         # use_diffusion
    ]
    _ssss.split_with_args.restype = ctypes.POINTER(ctypes.c_char_p)

    num_shares = ctypes.c_int()

    security_bits = secret.bit_length()
    if verbose:
        print(f"Security bits: {security_bits}")

    if verbose:
        print("\nCalling split_with_args with:")
        print(f"secret: {hex(secret)[2:]}")
        print(f"threshold: {ssss_threshold_shares}")
        print(f"num_shares: {ssss_num_shares}")
        print(f"use_hex: True")
        print(f"token: None")
        print(f"quiet: {not verbose}")
        print(f"num_output_shares: {num_shares.value}")
        print(f"security_bits: {security_bits}")
        print(f"use_diffusion: 0")

    shares_ptr = _ssss.split_with_args(
        str(hex(secret)[2:]).encode(),
        ssss_threshold_shares,
        ssss_num_shares,
        True, # use_hex mode
        None,
        not verbose,  # quiet
        ctypes.byref(num_shares),
        security_bits,
        0   # use_diffusion
    )
    return [(share.decode().split('-')[0].strip(), share.decode().split('-')[1].strip()) for share in (shares_ptr[i] for i in range(num_shares.value))]

def ssss_combine(shares, verbose=False):
    # Set up SSSS combine function
    _ssss = ctypes.CDLL('./libssss.so')
    _ssss.combine_with_args.argtypes = [
        ctypes.POINTER(ctypes.c_char_p),  # shares
        ctypes.c_int,                     # num_shares
        ctypes.c_int,                     # use_hex
        ctypes.c_int,                     # quiet
        ctypes.POINTER(ctypes.c_int)      # error
    ]

    # Convert shares to C array
    num_shares = len(shares)
    shares_array = (ctypes.c_char_p * num_shares)()
    for i, share in enumerate(shares):
        shares_array[i] = share.encode()

    error = ctypes.c_int()
    if verbose:
        print("\nCalling combine_with_args with:")
        print(f"shares: {[s.decode() for s in shares_array]}")
        print(f"num_shares: {num_shares}")
        print(f"use_hex: True")
        print(f"quiet: {not verbose}")
        print(f"error: {error.value}\n")

    _ssss.combine_with_args.restype = ctypes.c_char_p

    result = _ssss.combine_with_args(
        shares_array,
        num_shares,
        True, # use_hex mode
        not verbose,  # quiet
        ctypes.byref(error)
    )

    if error.value != 0:
        print("Error: Failed to combine shares")
        exit(1)

    return result.decode()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('operation', choices=['condense', 'expand', 'ssss-split', 'ssss-combine', 'full'],
                       help='Operation to perform: condense, expand, ssss-split, ssss-combine, full')
    args = parser.parse_args()

    if args.operation == "condense":
        m = input("Enter BIP39 mnemonic to condense to hex string: ").strip()
        print(f"\nCondensed mnemonic (hex): {hex(condense_mnemonic(m))[2:]}") # [2:] removes '0x' prefix

    elif args.operation == "expand":
        s = input("Enter hex string to expand to BIP39 mnemonic: ").strip()
        print(f"\nExpanded mnemonic: {expand_string_to_mnemonic(s)}")

    elif args.operation == "ssss-split":
        secret = input("Enter BIP39 secret phrase to split via SSSS: ").strip()

        num_shares = input("Enter number of shares to generate [5]: ").strip()
        ssss_num_shares = int(num_shares) if num_shares else 5
        
        threshold = input("Enter minimum shares needed to recover [3]: ").strip()
        ssss_threshold_shares = int(threshold) if threshold else 3

        shares = ssss_split(condense_mnemonic(secret), ssss_num_shares, ssss_threshold_shares, verbose=args.verbose)
        print("\nRaw Shares:")
        for i, share in shares:
            print(f"Share {i} (hex length: {len(share)}): {i}-{share}")
        
        mnemonic_shares = expand_shares_to_mnemonics(shares)
        print ("\nMnemonic Shares:")
        for i, mnemonic in mnemonic_shares:
            print(f"Share {i} (word length: {len(mnemonic)}): {' '.join(mnemonic)}")

    elif args.operation == "ssss-combine":
        num_recovery_shares = int(input("Enter number of shares you will use to recover the secret: ").strip())
        ssss_num_shares = int(num_recovery_shares) if num_recovery_shares else 3
        mnemonic_shares = []
        for i in range(num_recovery_shares):
            index = int(input(f"Enter share index: ").strip())
            share = input(f"Enter mnemonic share: ").strip()
            mnemonic_shares.append((index, share))
        print(f"\nMnemonic shares: {mnemonic_shares}")

        shares = condense_mnemonics_to_shares(mnemonic_shares)
        print(f"\nShares: {shares}")

        hex_shares = []
        for index, share in shares:
            hex_val = hex(share)[2:]  # [2:] removes '0x' prefix
            hex_shares.append(f"{index}-{hex_val}")

        print(f"\nHex shares: {hex_shares}")
        recovered_secret = ssss_combine(hex_shares)
        print(f"\nRecovered secret (hex): {hex(int(recovered_secret, 16))[2:]}")
        print(f"\nRecovered secret (mnemonic): {' '.join(expand_string_to_mnemonic(recovered_secret))}")

    elif args.operation == "full":
        print("Full operation not implemented yet.")
    