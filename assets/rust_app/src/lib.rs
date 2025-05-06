use wasm_bindgen::prelude::*;
mod message;
mod symmetric;
use message::Message;

#[wasm_bindgen]
pub fn encrypt_message(message: &str) -> String {
    let mut message = Message::new(message);
    return message.encrypt();
}
