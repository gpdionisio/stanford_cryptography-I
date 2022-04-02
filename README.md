# Cryptography I - Stanford University (Dan Boneh) - Coursera

Solutions of weekly assignments to practice Rust.

## Week 1: [Many Time Pad][w1]

Let us see what goes wrong when a stream cipher key is used more than once.  Below are eleven hex-encoded ciphertexts that are the result of encrypting eleven plaintexts with a stream cipher, all with the same stream cipher key.  Your goal is to decrypt the last ciphertext, and submit the secret message within it as solution.

## Week 2: [Many Time Blockciphers][w2]

In this project you will implement two encryption/decryption systems, one using AES in CBC mode and another using AES in counter mode (CTR).  In both cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext.

For CBC encryption we use the PKCS5 padding scheme discussed  in the lecture (14:04). While we ask that you implement both encryption and decryption, we will only test the decryption function.   In the following questions you are given an AES key and a ciphertext (both are  hex encoded ) and your goal is to recover the plaintext and enter it in the input boxes provided below.

## Week 3: [File Integrity][w3]

Our goal in this project is to build a file authentication system that lets browsers authenticate and play video chunks as they are downloaded without having to wait for the entire file. Instead of computing a hash of the entire file, the web site breaks the file into 1KB blocks (1024 bytes).  It computes the hash of the last block and appends the value to the second to last block.  It then computes the hash of this augmented second to last block and appends the resulting hash to the third block from the end.

## Week 4: [Padding Oracle Attack][w4]

Suppose an attacker wishes to steal secret information from our target web site  crypto-class.appspot.com . The attacker suspects that the web site embeds encrypted customer data in URL parameters such as this:

> http://crypto-class.appspot.com/po?er=f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4

That is, when customer Alice interacts with the site, the site embeds a URL like this in web pages it sends to Alice.  The attacker intercepts the URL listed above and guesses that the ciphertext following the "po?er=" is a hex encoded AES CBC encryption with a random IV of some secret data about Alice's session.

After some experimentation the attacker discovers that the web site is vulnerable to a CBC padding oracle attack. In particular, when a decrypted CBC ciphertext ends in an invalid pad the web server returns a 403 error code (forbidden request). When the CBC padding is valid, but the message is malformed, the web server returns a 404 error code (URL not found).

Armed with this information your goal is to decrypt the ciphertext listed above.

[w1]: week_01-many_time_pad/
[w2]: week_02-many_time_blockciphers/
[w3]: week_03-file_integrity/
[w4]: week_04-padding_oracle/
