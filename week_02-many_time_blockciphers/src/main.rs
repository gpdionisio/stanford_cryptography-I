use std::iter::repeat;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use rand::RngCore;
use rand::rngs::OsRng;


//use rand_core::OsRng;

const BLOCK_LEN: usize = 16;
type AesBlock = aes::Block;

// Create random initial value (nonce)
fn get_rand_iv() -> Vec<u8>
{
    let mut csprng = OsRng;
    let mut iv = vec![0u8; BLOCK_LEN];
    csprng.fill_bytes(&mut iv);
    iv
}

// Given an AES block x_a and a slice x_b, return a Vec with the xor of the two
fn xor(x_a: &AesBlock, x_b: &[u8]) -> Vec<u8>
{
    x_a.iter().zip(x_b).map(|(a, b)| a^b).collect()
}

// Decryption step (i) for CBC:
// given two consecutive blocks of ciphertext, C_(i-1) and C_i,
// return M_i = C_(i-1) ^ Dec[k, C_i]
fn cbc_step_dec(cipher: &Aes128, prev_block: &[u8], curr_block: &[u8]) -> Vec<u8>
{
    let mut d = AesBlock::clone_from_slice(curr_block);
    cipher.decrypt_block(&mut d);
    xor(&d, prev_block)
}

// nonce is the first block of ciphertext
fn decrypt_cbc(key_bytes: &[u8; BLOCK_LEN], ciphertext: &Vec<u8>) -> Result<Vec<u8>, String>
{
    if ciphertext.len() % BLOCK_LEN != 0 {
        return Err(format!("Invalid cyphertext length ({})", ciphertext.len()));
    }

    let key = AesBlock::from(*key_bytes);
    let cipher = Aes128::new(&key);

    let mut plaintext: Vec<u8> = ciphertext.chunks(BLOCK_LEN)
                                           .collect::<Vec<_>>()
                                           .windows(2)
                                           .map(|b| { cbc_step_dec(&cipher, b[0], b[1]) })
                                           .flatten().collect();

    let padding = *plaintext.last().unwrap() as usize;
    plaintext.truncate(plaintext.len() - padding);
    Ok(plaintext)
}

// Encryption step (i) for CBC:
// given the block of ciphertext, C_(i-1) and of plaintext M_i,
// return C_i = Enc[k, C_(i-1) ^ M_i]
fn cbc_step_enc(cipher: &Aes128, prev_block: &[u8], curr_block: &[u8]) -> Vec<u8>
{
    let x = xor(&AesBlock::from_slice(prev_block), curr_block);
    let mut d = AesBlock::clone_from_slice(x.as_slice());
    cipher.encrypt_block(&mut d);
    d.to_vec()
}

// nonce is the first block of ciphertext
// if the provided one is None, a new one is created
fn encrypt_cbc(key_bytes: &[u8; BLOCK_LEN], plaintext: &Vec<u8>, nonce: Option<&Vec<u8>>) -> Vec<u8>
{
    let mut ciphertext= match nonce {
        None => { get_rand_iv() }
        Some(x) => { x.clone() }
    };

    let key = AesBlock::from(*key_bytes);
    let cipher = Aes128::new(&key);

    let padding = BLOCK_LEN - plaintext.len() % BLOCK_LEN;

    plaintext.iter().cloned().chain(repeat(padding as u8).take(padding))
                    .collect::<Vec<_>>()
                    .chunks(BLOCK_LEN)
                    .scan(ciphertext.clone(), |ct, pt_block| {
                        let next_ct = cbc_step_enc(&cipher, ct, pt_block);
                        *ct = next_ct.to_vec();
                        Some(next_ct)
                    }).for_each(|b| ciphertext.extend_from_slice(&b));

    ciphertext
}

// Encryption/Decryption step (i) for CTR:
// given nonce iv and ciphertext block C_i
// return M_i = Enc[k, iv] ^ C_i
fn ctr_step(cipher: &Aes128, iv: u128, ct_block: &[u8]) -> Vec<u8>
{
    let mut pad = AesBlock::from(iv.to_be_bytes());
    cipher.encrypt_block(&mut pad);
    xor(&pad, &ct_block)
}

// nonce is the first block of ciphertext
fn decrypt_ctr(key_bytes: &[u8; BLOCK_LEN], ciphertext: &Vec<u8>) -> Vec<u8>
{
    let key = AesBlock::from(*key_bytes);
    let cipher = Aes128::new(&key);

    let mut iter = ciphertext.chunks(BLOCK_LEN);
    let iv = u128::from_be_bytes(iter.next().unwrap().try_into().unwrap());

    iter.enumerate()
        .flat_map(|(i, block)| {
            ctr_step(&cipher, iv + i as u128, block)
        }).collect()
}

// nonce is the first block of ciphertext
// if the provided one is None, a new one is created
fn encrypt_ctr(key_bytes: &[u8; BLOCK_LEN], plaintext: &Vec<u8>, nonce: Option<&Vec<u8>>) -> Vec<u8>
{
    let mut ciphertext= match nonce {
        None => { get_rand_iv() }
        Some(x) => { x.clone() }
    };

    let key = AesBlock::from(*key_bytes);
    let cipher = Aes128::new(&key);

    let iter = plaintext.chunks(BLOCK_LEN);
    let iv = u128::from_be_bytes(ciphertext.as_slice().try_into().unwrap());

    ciphertext.append(&mut iter.enumerate()
        .flat_map(|(i, block)| {
            ctr_step(&cipher, iv + i as u128, block)
        }).collect());
    ciphertext
}

enum AesType {
    CBC,
    CTR,
}

fn test_decrypt(key_bytes: &[u8; BLOCK_LEN], ciphertext: &Vec<u8>, dec_type: AesType, idx: u8) {
    match dec_type {
        AesType::CBC => {
            match decrypt_cbc(key_bytes, ciphertext) {
                Ok(plaintext) => { println!(
                    "plaintext-{} is: {}", idx,
                    String::from_utf8_lossy(&plaintext.as_slice()))
                }
                Err(e) => { println!(
                    "error decrypting ciphertext-{}: {}", idx, e)
                }
            }
        }
        AesType::CTR => {
            let plaintext = decrypt_ctr(key_bytes, ciphertext);
            println!("plaintext-{} is: {}", idx, String::from_utf8_lossy(&plaintext.as_slice()));
        }
    }
}

fn main() {
    let cbc_key: [u8; BLOCK_LEN] = hex::decode("140b41b22a29beb4061bda66b6747e14").unwrap().try_into().unwrap();
    let ctr_key: [u8; BLOCK_LEN] = hex::decode("36f18357be4dbd77f050515c73fcf9f2").unwrap().try_into().unwrap();
    let ciphertext_1 = hex::decode("4ca00ff4c898d61e1edbf1800618fb28\
                                                  28a226d160dad07883d04e008a7897ee\
                                                  2e4b7465d5290d0c0e6c6822236e1daa\
                                                  fb94ffe0c5da05d9476be028ad7c1d81").unwrap();
    let ciphertext_2 = hex::decode("5b68629feb8606f9a6667670b75b38a5\
                                                  b4832d0f26e1ab7da33249de7d4afc48\
                                                  e713ac646ace36e872ad5fb8a512428a\
                                                  6e21364b0c374df45503473c5242a253").unwrap();
    let ciphertext_3 = hex::decode("69dda8455c7dd4254bf353b773304eec\
                                                  0ec7702330098ce7f7520d1cbbb20fc3\
                                                  88d1b0adb5054dbd7370849dbf0b88d3\
                                                  93f252e764f1f5f7ad97ef79d59ce29f\
                                                  5f51eeca32eabedd9afa9329").unwrap();
    let ciphertext_4 = hex::decode("770b80259ec33beb2561358a9f2dc617\
                                                  e46218c0a53cbeca695ae45faa8952aa\
                                                  0e311bde9d4e01726d3184c34451").unwrap();
    test_decrypt(&cbc_key, &ciphertext_1, AesType::CBC, 1);
    test_decrypt(&cbc_key, &ciphertext_2, AesType::CBC, 2);
    test_decrypt(&ctr_key, &ciphertext_3, AesType::CTR, 3);
    test_decrypt(&ctr_key, &ciphertext_4, AesType::CTR, 4);

    // test encryption too
    let nonce: Vec<u8> = hex::decode("4ca00ff4c898d61e1edbf1800618fb28").unwrap();
    let mut pt = String::from("Basic CBC mode encryption needs padding.").into_bytes();
    assert_eq!(ciphertext_1, encrypt_cbc(&cbc_key, &mut pt, Some(&nonce)));
    assert_ne!(ciphertext_1, encrypt_cbc(&cbc_key, &mut pt, None));

    let nonce: Vec<u8> = hex::decode("5b68629feb8606f9a6667670b75b38a5").unwrap();
    let mut pt = String::from("Our implementation uses rand. IV").into_bytes();
    assert_eq!(ciphertext_2, encrypt_cbc(&cbc_key, &mut pt, Some(&nonce)));

    let nonce: Vec<u8> = hex::decode("69dda8455c7dd4254bf353b773304eec").unwrap();
    let mut pt = String::from("CTR mode lets you build a stream cipher from a block cipher.").into_bytes();
    assert_eq!(ciphertext_3, encrypt_ctr(&ctr_key, &mut pt, Some(&nonce)));
    assert_ne!(ciphertext_3, encrypt_ctr(&ctr_key, &mut pt, None));

    let nonce: Vec<u8> = hex::decode("770b80259ec33beb2561358a9f2dc617").unwrap();
    let mut pt = String::from("Always avoid the two time pad!").into_bytes();
    assert_eq!(ciphertext_4, encrypt_ctr(&ctr_key, &mut pt, Some(&nonce)));

}
