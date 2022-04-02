use itertools::Itertools;

const BLOCK_LEN: usize = 16;    // N

struct Oracle {
    http_client: reqwest::blocking::Client,
    serv_url: String,
}

impl Oracle {
    fn new(url: &str) -> Self {
        let http_client = reqwest::blocking::Client::new();
        Self { http_client, serv_url: url.to_string() }
    }

    // query the server for a given chiphertext
    // returns true if response status is 404 (good padding)
    // returns false if response status is 403 (bad padding)
    fn query(&self, cipher_str: &str) -> bool
    {
        let url = format!("{}{}", self.serv_url, cipher_str);
        return match self.http_client.get(url).send().ok() {
            None => {
                println!("No response");
                false
            }
            Some(response) => {
                let status = response.status().as_u16();
                if status != 403 && status != 404 {
                    println!("Invalid status code: {}", status);
                }
                status == 404
            }
        }
    }

    // Padding-Oracle attack to last unknown byte of plaintext block M_(j+1).
    // given ciphertext blocks C_j and C_(j+1), and vector [B_1, ..., B_k]
    // of already discovered bytes of M_(j+1) in reversed order (B_1 is the
    // last byte of M_(j+1), B_2 is the byte at index N-2, etc ..., B_k
    // is the byte at index N-k).
    // Represent (k+1) as the byte 'pad', and construct the block D_g as
    // D_g := [   C_j[0],
    //            C_j[1],
    //            ...,
    //            C_j[N-k-3],
    //            C_j[N-k-2],
    //            C_j[N-k-1] ^ pad ^ g,
    //            C_j[N-k] ^ pad ^ B_k,
    //            C_j[N-k+1] ^ pad ^ B_(k-1),
    //            ...,
    //            C_j[N-1] ^ pad ^ B_1   ]
    //
    // Submit the ciphertext D_g || C_(j+1) to check for valid padding
    // if valid --> g is the next byte. Otherwise increment it and try again.
    fn discover_next_byte(&self, prev_blk: &[u8], blk: &String, discovered: &[u8], start_guess: u8) -> Option<u8>
    {
        let next_guess_idx: usize = BLOCK_LEN - discovered.len() - 1;
        let pad: u8 = (discovered.len() as u8) + 1;

        let mut forged_ct: Vec<u8> = prev_blk.to_vec();
        for i in (next_guess_idx + 1)..BLOCK_LEN {
            forged_ct[i] = forged_ct[i] ^ discovered[BLOCK_LEN - 1 - i] ^ pad;
        }

        // pad, space, alphabetic chars
        for g in (1..17)
                   .chain(32..33)
                   .chain(65..91)
                   .chain(97..123)
                   .filter(|&x| x >= start_guess) {
            forged_ct[next_guess_idx] = prev_blk[next_guess_idx] ^ g ^ pad;
            let q = format!("{}{}", hex::encode(&forged_ct), blk);
            if self.query(&q) {
                println!("GOT {:0x?} (={})", g, g as char);
                return Some(g);
            }
        }
        None
    }

    fn decrypt_block(&self, prev_blk: &[u8], blk: &[u8]) -> Result<Vec<u8>, String>
    {
        let block_str = hex::encode(&blk);
        let mut pt_block: Vec<u8> = Vec::new();
        let mut start_guess: u8 = 0;
        loop {
            if let Some(b) = self.discover_next_byte(&prev_blk, &block_str, &pt_block, start_guess) {
                pt_block.push(b);
                start_guess = 0;
            } else {
                // remove the previous guess (if any) and retry. otherwise error
                start_guess = pt_block.pop().ok_or("Attack failed.")? + 1;
            }
            if pt_block.len() == BLOCK_LEN {
                break;
            }
        }
        pt_block.reverse();
        Ok(pt_block)
    }

    fn decrypt(&self, ct: &Vec<u8>) -> Result<Vec<u8>, String>
    {
        ct.chunks(BLOCK_LEN)
            .collect::<Vec<_>>().windows(2)
            .map(| a | self.decrypt_block(a[0], a[1]))
            .flatten_ok()
            .collect()
    }
}

fn main()
{
    let ct: Vec<u8> = hex::decode("f20bdba6ff29eed7b046d1df9fb70000\
                                        58b1ffb4210a580f748b4ac714c001bd\
                                        4a61044426fb515dad3f21f18aa577c0\
                                        bdf302936266926ff37dbf7035d5eeb4").unwrap();

    let padding_oracle = Oracle::new("http://crypto-class.appspot.com/po?er=");

    match padding_oracle.decrypt(&ct) {
        Ok(pt) => {
            // The Magic Words are Squeamish Ossifrage
            println!("FOUND: {}", String::from_utf8_lossy(&pt));
        }
        Err(e) => {
            println!("ERR: {}", e);
        }
    }
}
