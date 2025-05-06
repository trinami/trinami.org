use sha3::{Shake256, digest::{ExtendableOutput, XofReader, Update}};

use cipher::KeyIvInit;
//use cipher::generic_array::{GenericArray, typenum::{U32, U8}};
use cipher::StreamCipher;

use chacha20::ChaCha20Legacy;
use crate::symmetric::cipher::BlockCipher as SymmetricBlockCipher;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

pub const PADDING_LENGTH_INFORMATION_FIELD_SIZE: u64 = 1; //1 byte
pub const IV_SIZE: usize = 8; //64 bit, 8 byte
pub const BLOCK_SIZE: usize = 128; //128 byte

pub struct Message {
    data: Vec<u8>,
}

impl Message {
    pub fn new(message: &str) -> Self {
        Message {
            data: message.as_bytes().to_vec(),
        }
    }

    pub fn encrypt(&mut self) -> String {
        let (key1, key2, key3) = self.generate_keys();
        let mut iv = [0u8; IV_SIZE];
        getrandom::fill(&mut iv).unwrap();

        self.chacha20_xor(&key1, &iv);
        self.encrypt_cbc::<crate::symmetric::threefish::Threefish256Cipher>(&key2);
        self.encrypt_cbc::<crate::symmetric::aes::Aes256Cipher>(&key3);

        //append iv to the end of the data
        self.data.extend_from_slice(&iv);
        
        //return base64 encoded message
        BASE64.encode(&self.data)
    }

    fn chacha20_xor(&mut self, key: &[u8], iv: &[u8]) {
        let mut cipher = ChaCha20Legacy::new(key.into(), iv.into());
        cipher.apply_keystream(&mut self.data);
    }

    fn encrypt_cbc<C: SymmetricBlockCipher>(&mut self, key: &C::Key) {
        self.pad();
        
        let cipher = C::new(key);
        let mut last_block = vec![0u8; C::BLOCK_SIZE]; // Zero IV for first block
        let data_len = self.data.len();
        
        // Process all complete blocks
        for i in 0..(data_len / C::BLOCK_SIZE) {
            let block_start = i * C::BLOCK_SIZE;
            let block_end = block_start + C::BLOCK_SIZE;
            
            // XOR with previous block (or IV for first block)
            let mut block = vec![0u8; C::BLOCK_SIZE];
            block.copy_from_slice(&self.data[block_start..block_end]);
            
            for j in 0..C::BLOCK_SIZE {
                block[j] ^= last_block[j];
            }
            
            // Encrypt block
            cipher.encrypt_block(&mut block);
            
            // Write encrypted block back to data
            self.data[block_start..block_end].copy_from_slice(&block);
            
            // Save this encrypted block for next iteration
            last_block = block;
        }
    }

    fn generate_keys(&mut self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        let mut key3 = [0u8; 32];
        getrandom::fill(&mut key1).unwrap();
        getrandom::fill(&mut key2).unwrap();
        getrandom::fill(&mut key3).unwrap();

        return (key1, key2, key3)
    }

    fn pad(&mut self) {
        let message_size = self.data.len() as u64;
        let padding_length = (BLOCK_SIZE as u64) - ((message_size + PADDING_LENGTH_INFORMATION_FIELD_SIZE) % (BLOCK_SIZE as u64));
        
        // Create Shake256 hash of the message
        let mut shake = Shake256::default();
        shake.update(&self.data);
        
        // Generate padding bytes using XOF
        let mut padding_bytes = vec![0u8; padding_length as usize];
        let mut reader = shake.finalize_xof();
        XofReader::read(&mut reader, &mut padding_bytes);
        
        // Append padding bytes to the message
        self.data.extend_from_slice(&padding_bytes);
        
        // Append padding length information
        self.data.push(padding_length as u8);
    }

    /*fn unpad(&mut self) {
        if !self.data.is_empty() {
            let padding_length = *self.data.last().unwrap() as usize;
            let total_padding = padding_length + PADDING_LENGTH_INFORMATION_FIELD_SIZE as usize;
            self.data.truncate(self.data.len() - total_padding);
        }
    }*/
}
