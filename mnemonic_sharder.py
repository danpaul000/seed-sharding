import argparse
import ctypes
import math

def mnemonic_to_bytestring(mnemonic, word_list, bitshift):
    bytestring = 0
    for word in mnemonic:
        try:
            mnemonic_idx = word_list.index(word)
        except ValueError:
            raise Exception(f"{word} not found in the list")
        bytestring = (bytestring << bitshift) + mnemonic_idx
    return bytestring

def bytestring_to_mnemonic(s, word_list, bitshift):
    mnemonic = []
    while s > 0:
        idx = s & (2**bitshift - 1)
        mnemonic.insert(0, word_list[idx])  # Don't append or word list will come out reversed
        s = s >> bitshift
    return mnemonic

def ssss_split(secret, ssss_num_shares, ssss_threshold_shares, security_bits=None, verbose=False):
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
    if security_bits is None:
        security_bits = secret.bit_length()

    quiet = int(not verbose)

    if verbose:
        print("\nCalling split_with_args with:")
        print(f"secret: {hex(secret)[2:]}")
        print(f"threshold: {ssss_threshold_shares}")
        print(f"num_shares: {ssss_num_shares}")
        print(f"use_hex: True")
        print(f"token: None")
        print(f"quiet: {quiet}")
        print(f"num_output_shares: {num_shares.value}")
        print(f"security_bits: {security_bits}")
        print(f"use_diffusion: 0")

    shares_ptr = _ssss.split_with_args(
        str(hex(secret)[2:]).encode(),
        ssss_threshold_shares,
        ssss_num_shares,
        True, # use_hex mode
        None,
        quiet,  # quiet
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

    quiet = int(not verbose)
    error = ctypes.c_int()
    if verbose:
        print("\nCalling combine_with_args with:")
        print(f"shares: {[s.decode() for s in shares_array]}")
        print(f"num_shares: {num_shares}")
        print(f"use_hex: True")
        print(f"quiet: {quiet}")
        print(f"error: {error.value}\n")

    _ssss.combine_with_args.restype = ctypes.c_char_p

    result = _ssss.combine_with_args(
        shares_array,
        num_shares,
        True, # use_hex mode
        quiet,  # quiet
        ctypes.byref(error)
    )

    if error.value != 0:
        print("Error: Failed to combine shares")
        exit(1)

    return result.decode()

def prompt_for_secret():
    secret = input("Enter BIP39 secret phrase to split via SSSS: ").strip()

    num_shares = input("Enter number of shares to generate [5]: ").strip()
    ssss_num_shares = int(num_shares) if num_shares else 5

    threshold = input("Enter minimum shares needed to recover [3]: ").strip()
    ssss_threshold_shares = int(threshold) if threshold else 3
    return secret, ssss_num_shares, ssss_threshold_shares

def prompt_for_mnemonic_shares():
    num_recovery_shares = input("Enter number of shares you will use to recover the secret [3]: ").strip()
    ssss_num_recovery_shares = int(num_recovery_shares) if num_recovery_shares else 3
    mnemonic_shares = []
    for i in range(ssss_num_recovery_shares):
        index = int(input(f"Enter share index: ").strip())
        share = input(f"Enter mnemonic share: ").strip().split()
        mnemonic_shares.append((index, share))
    for i in range(len(mnemonic_shares) - 1):
        if len(mnemonic_shares[i]) != len(mnemonic_shares[i+1]):
            raise Exception("All mnemonic shares must contain the same number of words")
    return mnemonic_shares

# "secret" input is a mnemonic phrase, a single string of whitespace-separated words
# returns a list of length "n" tuples each containing share index and a mnemonic phrase as a list of words
def op_split(original_secret_expanded, n, t, wordlist, bitshift, verbose=False):
    original_secret_condensed = mnemonic_to_bytestring(original_secret_expanded.split(), wordlist, bitshift)

    print("\n###############\nOriginal Secret\n###############")
    print(f"(mnemonic): {original_secret_expanded}")
    print(f"(hex): {hex(original_secret_condensed)[2:]}")

    security_bits = len(original_secret_expanded.split()) * bitshift
    shares = ssss_split(original_secret_condensed, n, t, security_bits, verbose)
    print("\nSplit Secret - Raw Shares:")
    for i, share in shares:
        print(f"Share {i} (hex length: {len(share)}): {i}-{share}")

    mnemonic_shares = []
    for share_index, share_contents in shares:
        mnemonic = bytestring_to_mnemonic(int(share_contents, 16), wordlist, bitshift)
        mnemonic_shares.append((share_index, mnemonic))

    print ("\nSplit Secret - Mnemonic Shares:")
    for i, mnemonic in mnemonic_shares:
        print(f"Share {i} (word length: {len(mnemonic)}): {' '.join(mnemonic)}")

    return mnemonic_shares

# "mnemonic_shares" input is a list of tuples each containing share index and a mnemonic phrase as a list of words
# returns a mnemonic phrase as a string of whitespace-separated words
def op_combine(mnemonic_shares, wordlist, bitshift, verbose=False):

    if verbose:
        print(f"\nMnemonic shares for recombination:")
        for i, m_share in mnemonic_shares:
            print(i, ' '.join(m_share))

    int_shares = [(index, mnemonic_to_bytestring(mnemonic, wordlist, bitshift)) for index, mnemonic in mnemonic_shares]

    if verbose:
        print(f"\nInteger Shares for recombination:")
        for i_share in int_shares:
            print(i_share)

    min_hex_chars = len(mnemonic_shares[0][1]) / 4 * bitshift
    hex_shares = []
    for index, share in int_shares:
        hex_val = hex(share)[2:]  #  remove '0x' prefix
        zero_padding = ''.join('0' for i in range(int(min_hex_chars) - len(hex_val)))
        hex_shares.append(f"{index}-{zero_padding}{hex_val}")

    if verbose:
        print(f"\nHex shares for recombination:")
        for h_share in hex_shares:
            print(h_share)

    print("\n################\nRecovered Secret\n################")

    recovered_secret_condensed = ssss_combine(hex_shares, verbose)
    print(f"(hex): {hex(int(recovered_secret_condensed, 16))[2:]}")

    recovered_secret_expanded = ' '.join(bytestring_to_mnemonic(int(recovered_secret_condensed, 16), wordlist, bitshift))
    print(f"(mnemonic): {recovered_secret_expanded}")

    return recovered_secret_expanded

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-w', '--wordlist', type=str, help='Path to custom wordlist', default='english.txt')
    parser.add_argument('-b', '--bitshift', type=int, help='Bits per word (defaults to log2 of wordlist length)')
    parser.add_argument('operation', choices=['condense', 'expand', 'ssss-split', 'ssss-combine', 'full', 'none'],
                       help='Operation to perform: condense, expand, ssss-split, ssss-combine, full, none')
    args = parser.parse_args()

    with open(args.wordlist, "r", encoding="utf-8") as f:
        wordlist = [w.strip() for w in f.readlines()]

    if len(wordlist) & (len(wordlist) - 1) != 0:
        raise ValueError(f"Wordlist length ({len(wordlist)}) must be a power of 2")
    if not args.bitshift:
        bitshift = int(math.log2(len(wordlist)))
    else:
        bitshift = int(args.bitshift)

    if args.verbose:
        print(f"Wordlist length: {len(wordlist)}")
        print(f"Bitshift: {bitshift}")

    if args.operation == "condense":
        m = input("Enter BIP39 mnemonic to condense to hex string: ").strip()
        print(f"\nCondensed mnemonic (hex): {hex(mnemonic_to_bytestring(m.split(), wordlist, bitshift))[2:]}") # remove '0x' prefix

    elif args.operation == "expand":
        s = input("Enter hex string to expand to BIP39 mnemonic: ").strip()
        print(f"\nExpanded mnemonic: {bytestring_to_mnemonic(int(s, 16), wordlist, bitshift)}")

    elif args.operation == "ssss-split":
        secret, n, t = prompt_for_secret()
        op_split(secret, n, t, wordlist, bitshift, args.verbose)

    elif args.operation == "ssss-combine":
        mnemonic_shares = prompt_for_mnemonic_shares()
        op_combine(mnemonic_shares, wordlist, bitshift, args.verbose)

    elif args.operation == "full":
        original_secret, n, t = prompt_for_secret()
        mnemonic_shares = op_split(original_secret, n, t, wordlist, bitshift, args.verbose)
        recovered_secret = op_combine(mnemonic_shares[0:t], wordlist, bitshift, args.verbose)

        if recovered_secret == original_secret:
            print("Success! Recovered secret matches original secret.")
        else:
            print("!!! ERROR - Recovered secret does not match original secret !!!")