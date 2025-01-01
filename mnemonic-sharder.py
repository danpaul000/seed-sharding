import ssss
import argparse

def condense_mnemonic(word_list, mnemonic_phrase):
    bytestring = 0
    for word in mnemonic_phrase:
        try:
            mnemonic_idx = word_list.index(word)
        except ValueError:
            raise Exception("{word} not found in the list")
        bytestring = (bytestring << 11) + mnemonic_idx
    return bytestring

def expand_mnemonic(word_list, s):
    mnemonic_phrase = []
    while s > 0:
        idx = s & 0b11111111111
        mnemonic_phrase.insert(0, word_list[idx])  # Don't append or word list will come out reversed
        s = s >> 11
    return mnemonic_phrase

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s","--seed-phrase",
                        help="Seed phrase to shard. Will use dummy seed phrase if not provided",
                        default="velvet duty city expire credit base bronze turn exist learn rigid modify brother assist\
     amused antenna caught charge renew wide remain mixed gravity cave")
    parser.add_argument("-n", "--num-shares",
                        help="Number of shares to generate. Default: 5",
                        type=int,
                        default=5)
    parser.add_argument("-t", "--threshold-shares",
                        help="Minimum/threshold number of shares needed to recover original secret. Default: 3",
                        type=int,
                        default=3)
    args = parser.parse_args()

    seed_phrase_raw = args.seed_phrase
    ssss_num_shares = args.num_shares
    ssss_threshold_shares = args.threshold_shares

    original_seed_phrase = seed_phrase_raw.split()
    print("Original seed:\n", ' '.join(original_seed_phrase))

    d = "english.txt"
    with open(d, "r", encoding="utf-8") as f:
        bip39_wordlist = [w.strip() for w in f.readlines()]

    mnemonic_bytestring = condense_mnemonic(bip39_wordlist, original_seed_phrase)
    print("\nOriginal condensed seed:\n", mnemonic_bytestring)

    original_share_contents = ssss.make_random_shares(mnemonic_bytestring, ssss_threshold_shares, ssss_num_shares)
    print("\nOriginal share contents:")
    for i, share in original_share_contents:
        print(i, share)

    print("\nShares in mnemonic form:")
    all_share_mnemonics = []
    for i, share in original_share_contents:
        share_mnemonic = expand_mnemonic(bip39_wordlist, share)
        print(i, ' '.join(share_mnemonic))
        all_share_mnemonics.append(share_mnemonic)

    print("\n###################################")
    print("Sharded mnemonics created above.\nRecovery of original seed information using shares below.")
    print("###################################")

    print("\nRecover share contents from mnemonics:\n")
    # Run everything in reverse and rebuild original seed phrase
    recovered_share_contents=[]
    for i in range(len(all_share_mnemonics)):
        recovered_share_contents.append((i+1, condense_mnemonic(bip39_wordlist, all_share_mnemonics[i])))
        print("Recovered share:", recovered_share_contents[i],
              "Original share:", original_share_contents[i],
              "Match:", recovered_share_contents[i]==original_share_contents[i])

    recovered_condensed_secret = ssss.recover_secret(recovered_share_contents[:ssss_threshold_shares])
    print("\nRecombine one set of shares to recover condensed seed phrase:\n")
    print("Original condensed seed:", mnemonic_bytestring)
    print("Recovered condensed seed:", recovered_condensed_secret)
    if recovered_condensed_secret == mnemonic_bytestring:
        print("Recovery successful!")
    else:
        print("!!! ERROR: Recovery failed !!!")

    recovered_condensed_secret = ssss.recover_secret(recovered_share_contents[-ssss_threshold_shares:])
    print("\nRecombine a different set of shares to recover condensed seed phrase:\n")
    print("Original condensed seed:", mnemonic_bytestring)
    print("Recovered condensed seed:", recovered_condensed_secret)
    if recovered_condensed_secret == mnemonic_bytestring:
        print("Recovery successful!")
    else:
        print("!!! ERROR: Recovery failed !!!")

    recovered_seed_phrase = expand_mnemonic(bip39_wordlist, recovered_condensed_secret)
    print("\nOriginal seed phrase:\n", ' '.join(original_seed_phrase))
    print("Recovered seed phrase:\n", ' '.join(recovered_seed_phrase))

    if recovered_seed_phrase == original_seed_phrase:
        print("Recovery successful!")
    else:
        print("!!! ERROR: Recovery failed !!!")
