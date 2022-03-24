# Cryptography I - Stanford University (Dan Boneh) - Coursera

Solutions of weekly assignments to practice Rust.

## Week 1: [Many Time Pad][w1]

Let us see what goes wrong when a stream cipher key is used more than once.  Below are eleven hex-encoded ciphertexts that are the result of encrypting eleven plaintexts with a stream cipher, all with the same stream cipher key.  Your goal is to decrypt the last ciphertext, and submit the secret message within it as solution.

## Week 2: [Many Time Blockciphers][w2]

In this project you will implement two encryption/decryption systems, one using AES in CBC mode and another using AES in counter mode (CTR).  In both cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext.

For CBC encryption we use the PKCS5 padding scheme discussed  in the lecture (14:04). While we ask that you implement both encryption and decryption, we will only test the decryption function.   In the following questions you are given an AES key and a ciphertext (both are  hex encoded ) and your goal is to recover the plaintext and enter it in the input boxes provided below.

[w1]: week_01-many_time_pad/
[w2]: week_02-many_time_blockciphers/
