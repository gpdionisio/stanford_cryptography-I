use std::fs::{File};
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use sha2::{Digest, Sha256};

const BLOCK_SIZE: usize = 1024;

struct FileRevIter {
    file: File,
    file_size: u64,
    offset: i64,
}

impl FileRevIter
{
    fn new(path: &Path) -> io::Result<Self>
    {
        let file = File::open(path)?;
        let meta = file.metadata()?;
        Ok(Self {
            file,
            file_size: meta.len(),
            offset: (meta.len() % BLOCK_SIZE as u64) as i64
        })
    }
}

// return the byte chunk and its len
impl Iterator for FileRevIter
{
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset <= self.file_size as i64 {
            self.file.seek(SeekFrom::End(-self.offset)).unwrap();

            let mut buf: Vec<u8> = vec![0; BLOCK_SIZE];
            let len = self.file.read(&mut buf).unwrap();
            if len < BLOCK_SIZE {
                buf.truncate(len);
            }

            self.offset += BLOCK_SIZE as i64;
            return Some(buf);
        }
        None
    }
}

// iterates a file in reverse order in chunks of 1 KB (+leftover)
// start from h[n-1] = sha256(B_n) and f.e. i = (n-2)..0
// compute h[i] = sha256(B_(i+1) || h[i+1]),
// then returns the list h[n-1], h[n-2], ..., h[0]
fn get_block_hashes(path: &Path) -> io::Result<Vec<Vec<u8>>>
{
    let mut res: Vec<Vec<u8>> = Vec::new();
    let file_iter = FileRevIter::new(path)?;
    for mut v in file_iter {
        if let Some(hash) = res.last() {
            v.extend(hash);
        }
        let hash = Sha256::digest(&v).to_vec();
        res.push(hash);
    }
    Ok(res)
}

fn main()
{
    let block_hashes = get_block_hashes(Path::new("./data/6.1.intro.mp4")).unwrap();
    println!("h0 for file 1 is {}", hex::encode(block_hashes.last().unwrap()));

    let block_hashes = get_block_hashes(Path::new("./data/6.2.birthday.mp4")).unwrap();
    println!("h0 for file 2 is {}", hex::encode(block_hashes.last().unwrap()));
}
