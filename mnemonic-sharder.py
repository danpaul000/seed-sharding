import ssss

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

    ssss_num_shares = 5
    ssss_threshold_shards = 3

    dummy_seed_phrase = "velvet duty city expire credit base bronze turn exist learn rigid modify brother assist amused antenna caught charge renew wide remain mixed gravity cave"
    # dummy_seed_phrase = "velvet duty city expire credit base bronze turn exist learn rigid"
    seed_phrase = dummy_seed_phrase.split()

    print("Original seed:\n", ' '.join(seed_phrase))

    d = "english.txt"
    with open(d, "r", encoding="utf-8") as f:
        bip39_wordlist = [w.strip() for w in f.readlines()]

    mnemonic_bytestring = condense_mnemonic(bip39_wordlist, seed_phrase)
    print("\nOriginal condensed seed:\n", mnemonic_bytestring)

    original_shard_contents = ssss.make_random_shares(mnemonic_bytestring, ssss_threshold_shards, ssss_num_shares)
    print("\nOriginal shard contents:")
    for i, shard in original_shard_contents:
        print(i, shard)

    print("\nShards in mnemonic form:")
    all_shard_mnemonics = []
    for i, shard in original_shard_contents:
        shard_mnemonic = expand_mnemonic(bip39_wordlist, shard)
        print(i, ' '.join(shard_mnemonic))
        all_shard_mnemonics.append(shard_mnemonic)

    print("\n###################################")
    print("Sharded mnemonics created above.\nRecovery of original seed information using shards below.")
    print("###################################")

    print("\nRecover shard contents from mnemonics:\n")
    # Run everything in reverse and rebuild original seed phrase
    recovered_shard_contents=[]
    for i in range(len(all_shard_mnemonics)):
        recovered_shard_contents.append((i+1, condense_mnemonic(bip39_wordlist, all_shard_mnemonics[i])))
        print("Recovered shard:", recovered_shard_contents[i],
              "Original shard:", original_shard_contents[i],
              "Match:", recovered_shard_contents[i]==original_shard_contents[i])

    recovered_condensed_secret = ssss.recover_secret(recovered_shard_contents[:3])
    print("\nRecombine shards to recover condensed seed phrase:\n")
    print("Original condensed seed:", mnemonic_bytestring)
    print("Recovered condensed seed:", recovered_condensed_secret)

    if recovered_condensed_secret == mnemonic_bytestring:
        print("Recovery successful!")
    else:
        print("!!! ERROR: Recovery failed !!!")

    recovered_seed_phrase = expand_mnemonic(bip39_wordlist, recovered_condensed_secret)
    print("\nOriginal seed phrase:\n", ' '.join(seed_phrase))
    print("Recovered seed phrase:\n", ' '.join(recovered_seed_phrase))

    if recovered_seed_phrase == seed_phrase:
        print("Recovery successful!")
    else:
        print("!!! ERROR: Recovery failed !!!")
