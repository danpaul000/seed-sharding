# Mnemonic Sharding using Shamir's Secret Sharing Scheme

***WARNING: Absolutely no guarantees are made about the security or accuracy of this code!***

This program is designed to add an additional layer of security and redundancy for the cold storage self-custody of BIP39 mnemonics (seed phrases).
Uses Shamir's secret sharing scheme to take a BIP39 mnemonic for a seed phrase and create N arbitrary shares in BIP39 format of the same length, which can be stored separately.
M/N phrases are needed to recombine to recover the original seed phrase.
If any amount of mnemonic shares are lost or compromised, up to M-1, the original seed is still just as mathematically difficult to recover as if an attacker had 0 shares.

This program prompts the user to enter a plaintext mnemonic seed/secret which may represent a private key or seed.
Resulting shares are displayed in plaintext.

*Always verify the shares are correct before using them!*

***Use extreme caution when using any program (including this one) that deals with private keys/mnemonics!***

If using this program to shard a private key, please ensure that the private key is stored securely and that the mnemonic seed/secret is never revealed to anyone!
It is recommended to use a secure, offline computer to perform this operation when providing mnemonics that are used in production or used to store cryptoassets.

## Prerequisites
On a fresh Ubuntu 22.04 install the following:
```
sudo apt install git gcc make m4
```

Install The GNU Multiple Precision Arithmetic Library (GMP) from [here](https://gmplib.org/).  The following is the tested version for Ubuntu 22.04:
```
wget https://gmplib.org/download/gmp/gmp-6.3.0.tar.xz
tar xvf gmp-6.3.0.tar.xz
cd gmp-6.3.0
./configure
make
make check
make install
```

## Setup
Clone the repository and run the following:
```
git clone https://github.com/danpaul000/mnemonic-sharder.git
cd mnemonic-sharder
```

Compile ssss.c to libssss.so
```
gcc -c -fPIC ssss.c -o ssss.o
gcc -shared -o libssss.so ssss.o -lgmp
```

## Testing
`test.py` is a unit test for the mnemonic sharder.  It will test the mnemonic sharder with a set of fixed secrets and a set of random secrets.
All tests should pass and use 24-word mnemonics.
```
python3 test.py
```

## Standard Usage
```
python3 mnemonic_sharder.py --help
```

### Full Flow - Share Creation, Recombination and Verification
Run the full flow (share creation, recombination and verification) of the mnemonic sharder.
You will be prompted to enter the full mnemonic seed/secret as well as the desired number of shares and the threshold number of shares needed for recombination.
New shares are generated and displayed in plaintext.  The `full` operation will also recombine the shares using two different sets of shares and display the results, confirming if the original secret was successfully recovered.  When securely storing shares after they are created, you must note the displayed share number/index for each share, as well as the resulting mnemonic value.  The share number/index is required to recombine the shares.
```
python3 mnemonic_sharder.py full
```

### Share Creation
To create a new set of shares, run the `ssss-split` operation.  Resulting shares are displayed in plaintext as hex strings and mnemonics.
When securely storing shares after they are created, you must note the displayed share number/index for each share, as well as the resulting mnemonic value.  The share number/index is required to recombine the shares.
```
python3 mnemonic_sharder.py ssss-split
```

### Share Recombination
To recombine shares, run the `ssss-combine` operation.  The resulting secret is displayed in plaintext and should match the original mnemonic seed/secret.
```
python3 mnemonic_sharder.py ssss-combine
```

## Manual Verification of Shares using Linux Binary `ssss-combine`
`ssss.c` in this repository is a C implementation of Shamir's Secret Sharing Scheme.  It is used to generate the shares.  It is forked from http://point-at-infinity.org/ssss/ and is licensed under the GPLv2.
You can use the [original ssss implementation](http://point-at-infinity.org/ssss/) to manually verify the shares generated by `mnemonic_sharder.py`.

1) Create a new set of shares
```
python3 mnemonic_sharder.py ssss-split
```

2) Condense the resulting mnemonic shares to the hex strings they represent.  Run the `condense` operation N times, where N is threshold number of shares needed for recombination.
Note the associated share index for each resulting hex string.
```
python3 mnemonic_sharder.py condense
```

3) Recombine the shares using the `ssss-combine` binary, providing `THRESHOLD` as the threshold number of shares needed for recombination, which was set during the previous split operation.
Provide the share index and the resulting hex string for each share.  You must use the `-x` option to indicate that the shares will be provided in hex format. `ssss-combine` expects the shares in the following format: `[share index]-[hex string]`.
```
ssss-combine -x -t [THRESHOLD]
```

4) Expand the resulting hex string back to original mnemonic seed/secret.
```
python3 mnemonic_sharder.py expand
```

### Example Workflow - Creating new shares, manually condensing them to hex, and recombining using Linux binary`ssss-combine`, then expanding the result back to the original mnemonic seed/secret
```
$ python3 mnemonic_sharder.py ssss-split
Enter BIP39 secret phrase to split via SSSS: escape prefer shell boring wrap client pass rocket advance flee public clown expire exhaust mystery follow over good orchard sustain feature donate arrow nature
Enter number of shares to generate [5]:
Enter minimum shares needed to recover [3]:

###############
Original Secret
###############
(mnemonic): escape prefer shell boring wrap client pass rocket advance flee public clown expire exhaust mystery follow over good orchard sustain feature donate arrow nature
(hex): 4d153b158cffe055a82ddb03eb1ab41605069ee49ad59dec8e706d754282032c9b

Split Secret - Raw Shares:
Share 1 (hex length: 66): 1-c302b2ef251bc7d92e3d2883297432946df56c5cdc0e4983f6c7aeeb0fe7cb41cf
Share 2 (hex length: 66): 2-16a01b8f7f20ff6483bd035dacf6067170ea2cdebca57e801ef890b3609dc0ad6a
Share 3 (hex length: 66): 3-40765e82a64e35524ff93a59c1affef07ffda8c7d404f0278c7bc1c7add1bd6a85
Share 4 (hex length: 66): 4-285cb6e13cff7362c4c0b77a5c3aa745766c53d4c19c27c1efd716d2647d6c40fb
Share 5 (hex length: 66): 5-7e8af3ece591b95408848e7e31635fc4797bd7cda93da9667d5447a6a931118706

Split Secret - Mnemonic Shares:
Share 1 (word length: 24): seek better rookie enforce round uncle rib pink lobster entry arrow churn tent renew inflict limb end cabbage rapid fruit rail view code delay
Share 2 (word length: 24): birth absorb toilet wrestle avocado rather auction parrot frozen guilt light title attitude biology kit net leader abstract sail cannon current exclude actor pull
Share 3 (word length: 24): document real pass erode today powder divide chef flush aspect zero thought zone stamp butter letter usual detect bus logic kiss trip volcano expose
Share 4 (word length: 24): choose toss reunion ketchup warm ramp basic black kid tide prefer memory grocery clarify fantasy crime chief author volume color chaos dirt rain buyer
Share 5 (word length: 24): leader fiscal will sleep breeze present capital mushroom lawsuit mention subject material nut typical cute chicken practice crop fence monster hedgehog obtain ecology this

$ python3 mnemonic_sharder.py condense
Enter BIP39 mnemonic to condense to hex string: seek better rookie enforce round uncle rib pink lobster entry arrow churn tent renew inflict limb end cabbage rapid fruit rail view code delay

Condensed mnemonic (hex): c302b2ef251bc7d92e3d2883297432946df56c5cdc0e4983f6c7aeeb0fe7cb41cf
$ python3 mnemonic_sharder.py condense
Enter BIP39 mnemonic to condense to hex string: document real pass erode today powder divide chef flush aspect zero thought zone stamp butter letter usual detect bus logic kiss trip volcano expose

Condensed mnemonic (hex): 40765e82a64e35524ff93a59c1affef07ffda8c7d404f0278c7bc1c7add1bd6a85
$ python3 mnemonic_sharder.py condense
Enter BIP39 mnemonic to condense to hex string: leader fiscal will sleep breeze present capital mushroom lawsuit mention subject material nut typical cute chicken practice crop fence monster hedgehog obtain ecology this

Condensed mnemonic (hex): 7e8af3ece591b95408848e7e31635fc4797bd7cda93da9667d5447a6a931118706

$ ssss-combine -t 3 -x
Enter 3 shares separated by newlines:
Share [1/3]: 1-c302b2ef251bc7d92e3d2883297432946df56c5cdc0e4983f6c7aeeb0fe7cb41cf
Share [2/3]: 3-40765e82a64e35524ff93a59c1affef07ffda8c7d404f0278c7bc1c7add1bd6a85
Share [3/3]: 5-7e8af3ece591b95408848e7e31635fc4797bd7cda93da9667d5447a6a931118706
Resulting secret: 4d153b158cffe055a82ddb03eb1ab41605069ee49ad59dec8e706d754282032c9b

$ python3 mnemonic_sharder.py expand
Enter hex string to expand to BIP39 mnemonic: 4d153b158cffe055a82ddb03eb1ab41605069ee49ad59dec8e706d754282032c9b

Expanded mnemonic: escape prefer shell boring wrap client pass rocket advance flee public clown expire exhaust mystery follow over good orchard sustain feature donate arrow nature
```

# Disclaimer: Absolutely no guarantees are made about the security or accuracy of this code!
