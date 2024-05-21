//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.

use aes::{
	cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
	Aes128,
};
use rand::Rng;

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;
//We're assuming this is a random number generated
const IV: [u8; BLOCK_SIZE] = [10u8; BLOCK_SIZE];

fn main() {
	todo!("Maybe this should be a library crate. TBD");
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.encrypt_block(&mut block);

	block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
	// Convert the inputs to the necessary data type
	let mut block = GenericArray::from(data);
	let key = GenericArray::from(*key);

	let cipher = Aes128::new(&key);

	cipher.decrypt_block(&mut block);

	block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(mut data: Vec<u8>) -> Vec<u8> {
	// When twe have a multiple the second term is 0
	let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

	for _ in 0..number_pad_bytes {
		data.push(number_pad_bytes as u8);
	}

	data
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
	let mut blocks = Vec::new();
	let mut i = 0;
	while i < data.len() {
		let mut block: [u8; BLOCK_SIZE] = Default::default();
		block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
		blocks.push(block);

		i += BLOCK_SIZE;
	}

	blocks
}

/// Does the opposite of the group function
fn un_group(blocks: Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut data = Vec::new();
    for block in blocks {
        data.extend_from_slice(&block);
    }
    data
}

/// Does the opposite of the pad function.
fn un_pad(mut data: Vec<u8>) -> Vec<u8> {
    if let Some(&last_byte) = data.last() {
        let number_pad_bytes = last_byte as usize;
        data.truncate(data.len() - number_pad_bytes);
    }
    data
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
	// Pad the data so that it is a multiple of the block size
	let padded_data = pad(plain_text);

	// Group the data into blocks
	let blocks = group(padded_data);

	// Encrypt each block
	let mut ciphertext = Vec::new();
	for block in blocks {
		let encrypted_block = aes_encrypt(block, &key);
		ciphertext.push(encrypted_block);
	}

	// Ungroup the data
	let ciphertext_ungroup = un_group(ciphertext);

	ciphertext_ungroup
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    let ecb_group: Vec<[u8; BLOCK_SIZE]> = group(cipher_text);
    let decrypted_blocks : Vec<[u8; BLOCK_SIZE]> = ecb_group.into_iter().map(|block| aes_decrypt(block, &key)).collect();
    un_pad(un_group(decrypted_blocks))
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.´
    let padded_text = pad(plain_text);
    let grouped_text = group(padded_text);

    let mut prev_block = IV;

    let mut cipher_text = Vec::new();

	cipher_text.push(xor_vecs(IV, grouped_text[0]));

    for (i, block) in grouped_text.iter().enumerate().skip(1) {
        let mut xor_block = [0u8; BLOCK_SIZE];

        let encrypted_block = aes_encrypt(grouped_text[i - 1], &key);

		let xor_block = xor_vecs(*block, encrypted_block);

		cipher_text.push(xor_block);
    }

	let ciphertext_ungroup = un_group(cipher_text);

    ciphertext_ungroup
}


fn xor_vecs(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut result = [0; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}


fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	
	let mut decr_block:Vec<[u8; BLOCK_SIZE]> = vec![];
	let cipher_blocks = group(cipher_text);
	for cipher_block in cipher_blocks.iter(){
		decr_block.push(aes_decrypt(*cipher_block, &key));


	let mut xored_blocks:Vec<[u8; BLOCK_SIZE]> = vec![];
	for i in cipher_blocks.len()..0 {
		let xored = xor_vecs(cipher_blocks[i], cipher_blocks[i-1]);
		xored_blocks.push(xored);
	}
	xored_blocks.push(xor_vecs(cipher_blocks[0], IV));

	un_pad(un_group(xored_blocks))

}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
/// 

fn generate_nonce() -> [u8; 8] {
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill(&mut nonce);
    nonce
}

fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	// Remember to generate a random nonce
	let nonce = generate_nonce();
	let padded_data: Vec<u8> = pad(plain_text);
	let blocks = group(padded_data);
    let mut ciphertext = Vec::new();
    // Append the nonce to the beginning of the ciphertext
    ciphertext.extend_from_slice(&nonce);
    
    blocks.iter().enumerate().for_each(|(i, block)| {
        let mut counter_block = [0u8; BLOCK_SIZE];
        counter_block[..8].copy_from_slice(&nonce);
        counter_block[8..].copy_from_slice(&i.to_be_bytes());
        let encrypted_counter = aes_encrypt(counter_block, &key);
        let encrypted_block = xor_vecs(encrypted_counter, *block);
        ciphertext.extend_from_slice(&encrypted_block);
    });
    ciphertext
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
	todo!()
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_ecb_encrypt_decrypt() {
		let key = [0u8; 16];
		let plain_text = b"Hello, PBA!".to_vec();
		let cipher_text = super::ecb_encrypt(plain_text.clone(), key);
		let decrypted_text = super::ecb_decrypt(cipher_text, key);

		assert_eq!(plain_text, decrypted_text);
	}

	#[test]
	fn test_cbc_encrypt_decrypt() {
		let key = [0u8; 16];
		let plain_text = b"Hello, PBA!".to_vec();
		let cipher_text = super::cbc_encrypt(plain_text.clone(), key);
		let decrypted_text = super::cbc_decrypt(cipher_text, key);

		assert_eq!(plain_text, decrypted_text);
	}

	#[test]
	fn test_ctr_encrypt_decrypt() {
		let key = [0u8; 16];
		let plain_text = b"Hello, PBA!".to_vec();
		let cipher_text = super::ctr_encrypt(plain_text.clone(), key);
		let decrypted_text = super::ctr_decrypt(cipher_text, key);

		assert_eq!(plain_text, decrypted_text);
	}
}