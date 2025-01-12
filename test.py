import unittest
import random
from mnemonic_sharder import *

class TestMnemonicSharder(unittest.TestCase):

    def setUp(self):
        self.fixed_secrets = ["moment regret arrow chaos rocket trash merry glimpse father crush isolate seek acquire fat brisk tank unit entire current win slice quick aerobic grace",
                              "correct gesture vendor noodle artwork chat height grant flight network misery junk deputy source gentle illness surface dwarf sibling fork click plunge shaft improve",
                              "sort series monitor aisle goat prepare eternal tree flag supreme renew stable actor come humble ridge assist drive hungry immune insect approve airport sketch",
                              "ice fantasy purpose like potato person syrup south power task decline peanut general goat cheap expire enroll chief blame goat crash cradle barrel twelve",
                              "demand author erupt certain brick town leopard shuffle render citizen upgrade reunion local conduct nose club luggage penalty reunion culture earth erase economy degree"]

        with open("english.txt", "r", encoding="utf-8") as f:
            self.bip39_wordlist = [w.strip() for w in f.readlines()]

        num_secrets = 10
        words_per_secret = 24
        self.random_secrets = [' '.join([self.bip39_wordlist[random.randint(0,2047)] for i in range(words_per_secret)]) for j in range(num_secrets)]
        self.num_shares = 5
        self.threshold_shares = 3
        self.bitshift = int(math.log2(len(self.bip39_wordlist)))

    def test_fixed_secrets(self):
        for original_secret in self.fixed_secrets:
            print (f"Testing split and recominbation of: {original_secret}")
            mnemonic_shares = op_split(original_secret, self.num_shares, self.threshold_shares, self.bip39_wordlist, self.bitshift, verbose=True)
            recovered_hex = op_combine(mnemonic_shares, self.bip39_wordlist, self.bitshift, verbose=True)
            recovered_secret = ' '.join(bytestring_to_mnemonic(int(recovered_hex, 16), self.bip39_wordlist, self.bitshift))
            print(f"Original secret: {original_secret}")
            print(f"Recovered secret: {recovered_secret}")
            self.assertEqual(recovered_secret, original_secret, 'The recovered secret does not match original!')

    # def test_random_secrets(self):
    #     for original_secret in self.random_secrets:
    #         print (f"Testing split and recominbation of: {original_secret}")
    #         mnemonic_shares = op_split(original_secret, self.num_shares, self.threshold_shares, self.bip39_wordlist, self.bitshift, verbose=True)
    #         recovered_hex = op_combine(mnemonic_shares, self.bip39_wordlist, self.bitshift, verbose=True)
    #         recovered_secret = ' '.join(bytestring_to_mnemonic(int(recovered_hex, 16), self.bip39_wordlist, self.bitshift))
    #         print(f"Original secret: {original_secret}")
    #         print(f"Recovered secret: {recovered_secret}")
    #         self.assertEqual(recovered_secret, original_secret, 'The recovered secret does not match original!')

if __name__ == '__main__':
    unittest.main()