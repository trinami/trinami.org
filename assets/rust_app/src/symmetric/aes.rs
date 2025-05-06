use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use crate::symmetric::cipher::BlockCipher;

// Implementation for AES256
pub struct Aes256Cipher {
    cipher: aes::Aes256,
}

impl BlockCipher for Aes256Cipher {
    const BLOCK_SIZE: usize = 16;
    type Key = [u8; 32];
    
    fn new(key: &Self::Key) -> Self {
        let cipher = KeyInit::new_from_slice(key)
            .expect("Failed to initialize AES256 encryption cipher");
        Self { cipher }
    }
    
    fn encrypt_block(&self, block: &mut [u8]) {
        let mut block_array = GenericArray::from_mut_slice(block);
        BlockEncrypt::encrypt_block(&self.cipher, &mut block_array);
    }
}
