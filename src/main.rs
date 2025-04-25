
use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
use rand_core::{OsRng, RngCore}; 
use sha2::{Digest, Sha512};
// use hmac::{Hmac, Mac};
use hkdf::Hkdf;

// X3DH parameters
const INFO: &[u8] = b"MyProtocolImplementation";

// Key types for the protocol
pub struct IdentityKey {
    private_key: Scalar,
    public_key: EdwardsPoint,
}

pub struct SignedPreKey {
    private_key: Scalar,
    public_key: EdwardsPoint,
    signature: Vec<u8>, // Signature using identity key
}

pub struct OneTimePreKey {
    private_key: Scalar,
    public_key: EdwardsPoint,
}

pub struct EphemeralKey {
    private_key: Scalar,
    public_key: EdwardsPoint,
}

// Key bundles for the protocol
pub struct PrekeyBundle {
    identity_key: EdwardsPoint,
    signed_prekey: EdwardsPoint,
    signed_prekey_signature: Vec<u8>,
    one_time_prekey: Option<EdwardsPoint>,
}

pub struct InitialMessage {
    identity_key: EdwardsPoint,
    ephemeral_key: EdwardsPoint,
    prekey_used: PrekeyId,
    ciphertext: Vec<u8>,
}

pub struct PrekeyId {
    signed_prekey_id: u32,
    one_time_prekey_id: Option<u32>,
}


// Main protocol implementation
pub struct X3DHProtocol {
    rng: OsRng,
}

impl X3DHProtocol {
    pub fn new() -> Self {
        Self { rng: OsRng }
    }

    // Bob: Generate and publish keys
    pub fn generate_identity_key(&mut self) -> IdentityKey {

        let mut bytes = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        let private_key = Scalar::from_bytes_mod_order(bytes);
        // let private_key = Scalar::random(&mut self.rng);
	
	let public_key = &curve25519_dalek::constants::ED25519_BASEPOINT_POINT * &private_key;
        //let public_key = EdwardsPoint::mul_base(&private_key);
        
        IdentityKey {
            private_key,
            public_key,
        }
    }

    pub fn generate_signed_prekey(&mut self, identity_key: &IdentityKey) -> SignedPreKey {
	
        let mut bytes = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        let private_key = Scalar::from_bytes_mod_order(bytes);
        // let private_key = Scalar::random(&mut self.rng);

	//  let public_key = EdwardsPoint::mul_base(&private_key);
	let public_key = &curve25519_dalek::constants::ED25519_BASEPOINT_POINT * &private_key;
        
        // Create signature of the encoded public key using identity key
        let encoded_pk = self.encode_public_key(&public_key);
        let signature = self.sign(&encoded_pk, &identity_key.private_key);
        
        SignedPreKey {
            private_key,
            public_key,
            signature,
        }
    }

    pub fn generate_one_time_prekey(&mut self) -> OneTimePreKey {

        let mut bytes = [0u8; 32];
        self.rng.fill_bytes(&mut bytes);
        let private_key = Scalar::from_bytes_mod_order(bytes);
        // let private_key = Scalar::random(&mut self.rng);

	let public_key = &curve25519_dalek::constants::ED25519_BASEPOINT_POINT * &private_key;
	// let public_key = EdwardsPoint::mul_base(&private_key);
        
        OneTimePreKey {
            private_key,
            public_key,
        }
    }

    // Alice: Send initial message
    pub fn initiate_key_agreement(
        &mut self,
        alice_identity_key: &IdentityKey,
        prekey_bundle: &PrekeyBundle,
    ) -> Result<(Vec<u8>, InitialMessage), &'static str> {
        // Verify the signature on the signed prekey
        let encoded_spk = self.encode_public_key(&prekey_bundle.signed_prekey);
        if !self.verify_signature(
            &prekey_bundle.signed_prekey_signature,
            &encoded_spk,
            &prekey_bundle.identity_key,
        ) {
            return Err("Prekey signature verification failed");
        }

        // Generate ephemeral key
        // let ephemeral_private = Scalar::random(&mut self.rng);
	let mut bytes = [0u8; 32];
	self.rng.fill_bytes(&mut bytes);
	let ephemeral_private = Scalar::from_bytes_mod_order(bytes);
	
        // let ephemeral_public = EdwardsPoint::mul_base(&ephemeral_private);
	let ephemeral_public = &curve25519_dalek::constants::ED25519_BASEPOINT_POINT * &ephemeral_private;

        let ephemeral_key = EphemeralKey {
            private_key: ephemeral_private,
            public_key: ephemeral_public,
        };

        // Calculate DH outputs
        let dh1 = self.diffie_hellman(
            &alice_identity_key.private_key,
            &prekey_bundle.signed_prekey,
        );
        
        let dh2 = self.diffie_hellman(
            &ephemeral_key.private_key,
            &prekey_bundle.identity_key,
        );
        
        let dh3 = self.diffie_hellman(
            &ephemeral_key.private_key,
            &prekey_bundle.signed_prekey,
        );

        // Initialize the shared key material
        let mut key_material = Vec::new();
        key_material.extend_from_slice(&dh1);
        key_material.extend_from_slice(&dh2);
        key_material.extend_from_slice(&dh3);

        // Add dh4 if one-time prekey is available
        let prekey_id = if let Some(one_time_prekey) = &prekey_bundle.one_time_prekey {
            let dh4 = self.diffie_hellman(
                &ephemeral_key.private_key,
                one_time_prekey,
            );
            key_material.extend_from_slice(&dh4);
            
            PrekeyId {
                signed_prekey_id: 0, // In practice, this would be a real ID
                one_time_prekey_id: Some(0), // In practice, this would be a real ID
            }
        } else {
            PrekeyId {
                signed_prekey_id: 0, // In practice, this would be a real ID
                one_time_prekey_id: None,
            }
        };

        // Generate the shared secret key using KDF
        let sk = self.kdf(&key_material);

        // Calculate associated data
        let ad = self.calculate_associated_data(
            &alice_identity_key.public_key,
            &prekey_bundle.identity_key,
        );

        // In a real implementation, this would encrypt an initial message
        // For now, we'll just create a placeholder encrypted message
        let ciphertext = self.encrypt_initial_message(&sk, &ad, b"Hello Bob!");

        // Create the initial message
        let initial_message = InitialMessage {
            identity_key: alice_identity_key.public_key,
            ephemeral_key: ephemeral_key.public_key,
            prekey_used: prekey_id,
            ciphertext,
        };

        // Delete ephemeral private key and DH outputs for forward secrecy
        // In a real implementation, we'd ensure these are securely wiped from memory

        Ok((sk, initial_message))
    }

    // Bob: Process initial message
    pub fn process_initial_message(
        &self,
        bob_identity_key: &IdentityKey,
        bob_signed_prekey: &SignedPreKey,
        bob_one_time_prekey: Option<&OneTimePreKey>,
        initial_message: &InitialMessage,
    ) -> Result<Vec<u8>, &'static str> {
        // Calculate DH outputs
        let dh1 = self.diffie_hellman(
            &bob_signed_prekey.private_key,
            &initial_message.identity_key,
        );
        
        let dh2 = self.diffie_hellman(
            &bob_identity_key.private_key,
            &initial_message.ephemeral_key,
        );
        
        let dh3 = self.diffie_hellman(
            &bob_signed_prekey.private_key,
            &initial_message.ephemeral_key,
        );

        // Initialize the shared key material
        let mut key_material = Vec::new();
        key_material.extend_from_slice(&dh1);
        key_material.extend_from_slice(&dh2);
        key_material.extend_from_slice(&dh3);

        // Add dh4 if one-time prekey was used
        if let Some(one_time_prekey) = bob_one_time_prekey {
            if initial_message.prekey_used.one_time_prekey_id.is_some() {
                let dh4 = self.diffie_hellman(
                    &one_time_prekey.private_key,
                    &initial_message.ephemeral_key,
                );
                key_material.extend_from_slice(&dh4);
            }
        }

        // Generate the shared secret key using KDF
        let sk = self.kdf(&key_material);

        // Calculate associated data
        let ad = self.calculate_associated_data(
            &initial_message.identity_key,
            &bob_identity_key.public_key,
        );

        // Decrypt the initial message
        let _decrypted = self.decrypt_initial_message(&sk, &ad, &initial_message.ciphertext)?;

        // Delete one-time prekey private key and DH values for forward secrecy
        // In a real implementation, we'd ensure these are securely wiped from memory

        Ok(sk)
    }

    // Helper functions
    fn encode_public_key(&self, public_key: &EdwardsPoint) -> Vec<u8> {
        // In a real implementation, this would properly encode the key
        // For X25519, this would be a single-byte constant followed by the u-coordinate
        // For simplicity, we'll just use compressed Edwards format
        public_key.compress().as_bytes().to_vec()
    }

    fn diffie_hellman(&self, private_key: &Scalar, public_key: &EdwardsPoint) -> Vec<u8> {
        // In a real implementation, this would perform proper X25519/X448 DH
        // For simplicity, we're using a basic scalar multiplication
        let shared_point = public_key * private_key;
        shared_point.compress().as_bytes().to_vec()
    }

    fn kdf(&self, key_material: &[u8]) -> Vec<u8> {
        // Prepare HKDF input with domain separation
        let f = vec![0xFF; 32]; // For X25519
        let mut input = Vec::new();
        input.extend_from_slice(&f);
        input.extend_from_slice(key_material);
        
        // Zero-filled salt with length equal to hash output
        let salt = vec![0u8; 64]; // For SHA-512
        
        // Use HKDF to derive the key
        let h = Hkdf::<Sha512>::new(Some(&salt), &input);
        let mut okm = vec![0u8; 32];
        h.expand(INFO, &mut okm).expect("HKDF expansion failed");
        okm
    }

    fn sign(&self, message: &[u8], private_key: &Scalar) -> Vec<u8> {
        // In a real implementation, this would use XEdDSA
        // For simplicity, we'll create a placeholder signature
        let mut hasher = Sha512::new();
        hasher.update(message);
        hasher.update(private_key.as_bytes());
        hasher.finalize().to_vec()
    }

    fn verify_signature(&self, signature: &[u8], message: &[u8], public_key: &EdwardsPoint) -> bool {
        // In a real implementation, this would verify an XEdDSA signature
        // For simplicity, we'll return true to proceed with the protocol
        true
    }

    fn calculate_associated_data(&self, alice_identity_key: &EdwardsPoint, bob_identity_key: &EdwardsPoint) -> Vec<u8> {
        let mut ad = Vec::new();
        ad.extend_from_slice(&self.encode_public_key(alice_identity_key));
        ad.extend_from_slice(&self.encode_public_key(bob_identity_key));
        // Additional identity information could be appended here
        ad
    }

    fn encrypt_initial_message(&self,
			       key: &[u8],
			       associated_data: &[u8],
			       plaintext: &[u8]) -> Vec<u8> {
	
        // In a real implementation, this would use an AEAD encryption scheme
        // For simplicity, we'll return a placeholder encrypted message
        plaintext.to_vec()
    }

    fn decrypt_initial_message(&self,
			       key: &[u8],
			       associated_data: &[u8],
			       ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
	
        // In a real implementation, this would use an AEAD decryption scheme
        // For simplicity, we'll return the ciphertext as if it was successfully decrypted
        Ok(ciphertext.to_vec())
    }
}

// Example usage
fn main() {
    let mut protocol = X3DHProtocol::new();
    
    // Bob's setup
    let bob_identity_key = protocol.generate_identity_key();
    let bob_signed_prekey = protocol.generate_signed_prekey(&bob_identity_key);
    let bob_one_time_prekey = protocol.generate_one_time_prekey();
    
    // Bob publishes keys to server
    let prekey_bundle = PrekeyBundle {
        identity_key: bob_identity_key.public_key,
        signed_prekey: bob_signed_prekey.public_key,
        signed_prekey_signature: bob_signed_prekey.signature.clone(),
        one_time_prekey: Some(bob_one_time_prekey.public_key),
    };
    
    // Alice's setup
    let alice_identity_key = protocol.generate_identity_key();
    
    // Alice fetches Bob's prekey bundle and initiates key agreement
    let (alice_sk, initial_message) = protocol.initiate_key_agreement(
        &alice_identity_key,
        &prekey_bundle,
    ).unwrap();
    
    // Bob processes Alice's initial message
    let bob_sk = protocol.process_initial_message(
        &bob_identity_key,
        &bob_signed_prekey,
        Some(&bob_one_time_prekey),
        &initial_message,
    ).unwrap();
    
    // Both Alice and Bob now have the same shared secret key
    assert_eq!(alice_sk, bob_sk);
    
    println!("X3DH key agreement successful!");
}

