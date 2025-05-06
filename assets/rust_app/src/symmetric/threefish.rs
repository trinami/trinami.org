use threefish::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use crate::symmetric::cipher::BlockCipher;

// Implementation for Threefish
pub struct Threefish1024Cipher {
    cipher: threefish::Threefish1024,
}

impl BlockCipher for Threefish1024Cipher {
    const BLOCK_SIZE: usize = 128;
    type Key = [u8; 128];
    
    fn new(key: &Self::Key) -> Self {
        let cipher = KeyInit::new_from_slice(key)
            .expect("Failed to initialize Threefish cipher");
        Self { cipher }
    }
    
    fn encrypt_block(&self, block: &mut [u8]) {
        let mut block_array = GenericArray::from_mut_slice(block);
        BlockEncrypt::encrypt_block(&self.cipher, &mut block_array);
    }
}

// Implementation for Threefish
pub struct Threefish256Cipher {
    cipher: threefish::Threefish256,
}

impl BlockCipher for Threefish256Cipher {
    const BLOCK_SIZE: usize = 32;
    type Key = [u8; 32];
    
    fn new(key: &Self::Key) -> Self {
        let cipher = KeyInit::new_from_slice(key)
            .expect("Failed to initialize Threefish cipher");
        Self { cipher }
    }
    
    fn encrypt_block(&self, block: &mut [u8]) {
        let mut block_array = GenericArray::from_mut_slice(block);
        BlockEncrypt::encrypt_block(&self.cipher, &mut block_array);
    }
}
