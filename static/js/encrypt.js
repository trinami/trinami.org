async function encrypt()
{
    //ECC+chacha20
    var key1 = new Uint8Array(32);
    crypto.getRandomValues(key1);
    //mceliece+aes
    var key2 = new Uint8Array(32);
    crypto.getRandomValues(key2);
    //
    var key3 = new Uint8Array(32);
    crypto.getRandomValues(key3);
   
    var original_text = new TextEncoder().encode(document.getElementsByTagName("textarea")[0].value);
    const sha512_hash = await crypto.subtle.digest("SHA-512", original_text);
    const padding_length = 64 - ((original_text.length + 1) % 64);
    
    // Create a new Uint8Array with enough space for original text + length byte + padding
    var encoded_text = new Uint8Array(original_text.length + 1 + padding_length);
    
    // Copy original text
    encoded_text.set(original_text);
    
    // Add length byte
    encoded_text[original_text.length] = original_text.length;
    
    // Add padding
    for(let i = 0; i < padding_length; i++)
    {
        encoded_text[original_text.length + 1 + i] = sha512_hash[i];
    }

    console.log(original_text);
    console.log(sha512_hash);
    console.log(encoded_text);
}
