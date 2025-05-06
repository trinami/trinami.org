use kuznyechik::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use crate::symmetric::cipher::BlockCipher;

// Implementation for Kuznyechik
pub struct KuznyechikCipher {
    cipher: kuznyechik::KuznyechikEnc,
}

impl BlockCipher for KuznyechikCipher {
    const BLOCK_SIZE: usize = 16;
    type Key = [u8; 32];
    
    fn new(key: &Self::Key) -> Self {
        let cipher = KeyInit::new_from_slice(key)
            .expect("Failed to initialize Kuznyechik encryption cipher");
        Self { cipher }
    }
    
    fn encrypt_block(&self, block: &mut [u8]) {
        let mut block_array = GenericArray::from_mut_slice(block);
        BlockEncrypt::encrypt_block(&self.cipher, &mut block_array);
    }
}
