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

        self.verbose = False

    def test_fixed_secrets(self):
        for secret in self.fixed_secrets:
            self.run_split_and_combine(secret)
    def test_random_secrets(self):
        for secret in self.random_secrets:
            self.run_split_and_combine(secret)

    def run_split_and_combine(self, original_secret):
        mnemonic_shares = op_split(original_secret, self.num_shares, self.threshold_shares, self.bip39_wordlist, self.bitshift, verbose=self.verbose)

        recovered_secret_first_combo = op_combine(mnemonic_shares[0:self.threshold_shares], self.bip39_wordlist, self.bitshift, verbose=self.verbose)
        recovered_secret_second_combo = op_combine(mnemonic_shares[-self.threshold_shares:], self.bip39_wordlist, self.bitshift, verbose=self.verbose)

        print(f"Original secret: {original_secret}")
        print(f"Recovered secret (first set of shares): {recovered_secret_first_combo}")
        print(f"Recovered secret (second set of shares): {recovered_secret_second_combo}")

        self.assertEqual(original_secret, recovered_secret_first_combo, 'The recovered secret does not match original!')
        self.assertEqual(recovered_secret_first_combo, recovered_secret_second_combo, 'Different recovery share combinations resulted in different secrets!')


if __name__ == '__main__':
    unittest.main()