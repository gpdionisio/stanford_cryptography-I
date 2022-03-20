use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn find_key(key: &mut Vec<u8>, c1: &Vec<u8>, c2: &Vec<u8>, c3: &Vec<u8>) {
    // Idea:
    // - construct c1 xor c2, c1 xor c3, c2 xor c3
    // - if at position i, e.g. (c1 xor c2) and (c1 xor c3) is a valid ACII
    //   then we infer that m1[i] is a space
    // - then key[i] = c1[i] xor ' '

    let min_len = [c1.len(), c2.len(), c3.len()].iter().min().unwrap().clone();

    assert!(key.len() >= min_len);

    for i in 0..min_len {
        if key[i] != 0 {
            continue;
        }
        let c12 = (c1[i] ^ c2[i]).is_ascii_alphabetic();
        let c13 = (c1[i] ^ c3[i]).is_ascii_alphabetic();
        let c23 = (c2[i] ^ c3[i]).is_ascii_alphabetic();
        if c12 && c13 {
            key[i] = c1[i] ^ b' ';
        } else if c12 && c23 {
            key[i] = c2[i] ^ b' ';
        } else if c23 && c13 {
            key[i] = c3[i] ^ b' ';
        }
    }
}

fn recover_key(key: &mut Vec<u8>, ciphertexts: &Vec<Vec<u8>>) {
    for i in 0..(ciphertexts.len() - 2) {
        for j in (i + 1)..(ciphertexts.len() - 1) {
            for k in (j+1)..ciphertexts.len() {
                find_key(key, &ciphertexts[i], &ciphertexts[j], &ciphertexts[k]);
            }
        }
    }
}

fn decrypt(key: &Vec<u8>, ciphertexts: &Vec<Vec<u8>>) -> Vec<Vec<u8>>
{
    let mut plaintexts: Vec<Vec<u8>> = Vec::new();

    for (i, ct) in ciphertexts.iter().enumerate() {
        plaintexts.push(Vec::new());
        for j in 0..ct.len() {
            plaintexts[i].push(key[j] ^ ct[j]);
        }
    }

    plaintexts
}

fn read_lines<P>(filename: P) -> io::Lines<io::BufReader<File>>
    where P: AsRef<Path>, {
    match File::open(filename) {
        Ok(file) => { io::BufReader::new(file).lines() }
        Err(e) => { panic!("Problems opening file: {:?}", e) }
    }
}

fn main() {
    let mut ciphertexts: Vec<Vec<u8>> = Vec::new();
    let lines= read_lines("ciphertexts.txt");
    for (i, line) in lines.enumerate() {
        if let Ok(ct_hex) = line {
            ciphertexts.push(hex::decode(ct_hex).unwrap());
        }
    }
    let max_len = ciphertexts.iter().map(|x| x.len()).max().unwrap().clone();
    println!("Max len is {}", max_len);
    let mut key: Vec<u8> = vec![0; max_len];
    recover_key(&mut key, &ciphertexts);

    println!("Recovered key: {:x?}", key.as_slice());

    println!("Trying to decrypt...");
    let plaintexts = decrypt(&key, &ciphertexts);
    let m = String::from_utf8_lossy(plaintexts.last().unwrap().as_slice());
    println!("{}", m);

    println!("Fixing...");
    for (i, x) in plaintexts.last().unwrap().iter().enumerate() {
        println!("{}) {}", i, *x as char);
    }

    // 8-th char in last plaintext should not be 'u', it's probably 'r'
    // ct[6] ^ key[6] = b'u' ==> key[6] = key[6] ^ b'u' ^ b'r'
    // etc...
    key[7] = key[7] ^ b'u' ^ b'r';
    key[20] = key[20] ^ b'>' ^ b's';
    key[25] = key[25] ^ b't' ^ b'e';
    key[26] = key[26] ^ b'!' ^ b'n';
    key[31] = key[31] ^ b'&' ^ b'n';
    key[35] = key[35] ^ b'a' ^ b' ';
    key[36] = key[36] ^ b'~' ^ b's';
    key[50] = key[50] ^ b'.' ^ b' ';
    key[57] = key[57] ^ b';' ^ b'u';
    key[63] = key[63] ^ b'7' ^ b'e';
    key[70] = key[70] ^ b' ' ^ b'o';
    key[81] = key[81] ^ b'7' ^ b'c';
    key[82] = key[82] ^ b'6' ^ b'e';
    key[83] = key[83] ^ b'A' ^ b' ';
    key[84] = key[84] ^ b'<' ^ b'r';
    key[86] = key[86] ^ b'Z' ^ b'd';
    key[89] = key[89] ^ b'(' ^ b'e';
    key[92] = key[92] ^ b'\xDA' ^ b'b';
    key[96] = key[96] ^ b't' ^ b' ';
    key[99] = key[99] ^ b'f' ^ b'd';
    key[101] = key[101] ^ b'\xB2' ^ b't';
    key[102] = key[102] ^ b'o' ^ b'h';
    key[103] = key[103] ^ b'2' ^ b'a';
    key[109] = key[109] ^ b'\xA9' ^ b'c';
    key[110] = key[110] ^ b'8' ^ b'h';
    key[113] = key[113] ^ b'\x08' ^ b'i';
    key[114] = key[114] ^ b'>' ^ b'l';
    key[115] = key[115] ^ b'a' ^ b'l';
    key[118] = key[118] ^ b'N' ^ b'e';
    key[119] = key[119] ^ b'i' ^ b'e';
    key[122] = key[122] ^ b'\x7F' ^ b's';
    key[124] = key[124] ^ b' ' ^ b'c';
    key[125] = key[125] ^ b';' ^ b'r';
    key[128] = key[128] ^ b'5' ^ b's';
    key[131] = key[131] ^ b'\x0C' ^ b'a';
    key[135] = key[135] ^ b'\x0B' ^ b'r';
    key[136] = key[136] ^ b'\x13' ^ b'n';
    key[137] = key[137] ^ b'\xE7' ^ b'm';
    key[138] = key[138] ^ b'\x22' ^ b'e';
    key[140] = key[140] ^ b'\xFF' ^ b't';
    key[142] = key[142] ^ b'q' ^ b'u';
    key[144] = key[144] ^ b'd' ^ b' ';
    key[145] = key[145] ^ b'c' ^ b'e';
    key[146] = key[146] ^ b'\xAB' ^ b'c';
    key[147] = key[147] ^ b'\x15' ^ b'r';
    key[149] = key[149] ^ b'\x20' ^ b'p';
    key[150] = key[150] ^ b'\x85' ^ b't';
    key[151] = key[151] ^ b'w' ^ b'm';
    key[152] = key[152] ^ b'\xAC' ^ b'e';
    key[153] = key[153] ^ b'\xE7' ^ b'n';
    key[154] = key[154] ^ b'\x20' ^ b't';
    key[155] = key[155] ^ b'\x88' ^ b' ';
    key[156] = key[156] ^ b'\xE0' ^ b'o';
    key[157] = key[157] ^ b'\xA3' ^ b'r';
    key[158] = key[158] ^ b'\xB8' ^ b'c';
    key[159] = key[159] ^ b'\x94' ^ b'e';
    key[160] = key[160] ^ b'G' ^ b' ';
    key[161] = key[161] ^ b'<' ^ b't';
    key[162] = key[162] ^ b'\x1B' ^ b'o';
    key[163] = key[163] ^ b'\xBE' ^ b' ';
    key[164] = key[164] ^ b'\xB6' ^ b'b';
    key[165] = key[165] ^ b'\xB4' ^ b'r';
    key[166] = key[166] ^ b'\x91' ^ b'e';
    key[167] = key[167] ^ b':' ^ b'a';
    key[168] = key[168] ^ b'S' ^ b'k';
    key[169] = key[169] ^ b'l' ^ b' ';
    key[170] = key[170] ^ b'\xE4' ^ b'y';
    key[171] = key[171] ^ b'\xF9' ^ b'o';
    key[172] = key[172] ^ b'\xB1' ^ b'u';
    key[173] = key[173] ^ b'?' ^ b'.';

    println!("Trying to decrypt again...");
    let plaintexts = decrypt(&key, &ciphertexts);
    for (i, pt) in plaintexts.iter().enumerate() {
        let m = String::from_utf8_lossy(pt.as_slice());
        println!("plaintext {}: {}", i, m);
    }

}
