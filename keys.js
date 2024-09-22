// Imports
const forge = require('node-forge');

// KeyManager class to manage keys
class KeyManager {
  constructor() {
    this.keys = {}; // Initialize keys as an empty object
  }

  // Generate a new key pair with the specified key ID and expiration time
  generateKey(kid, expiresIn) {

    // Generate a new RSA key pair (2048 bits)
    const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair(2048);
    // Calculate expiration time in milliseconds
    const expiration = Date.now() + expiresIn * 1000;

    // Store the key pair in the keys object
    this.keys[kid] = {
      private: forge.pki.privateKeyToPem(privateKey), // Convert private key to PEM format
      public: forge.pki.publicKeyToPem(publicKey),    // Convert public key to PEM format
      expiration,                                     // Expiration time in milliseconds
    };
  }

  // Get valid keys that have not expired
  getValidKeys() {
    return Object.entries(this.keys).reduce((validKeys, [kid, keyData]) => {
      // Check if the key has not expired
      if (keyData.expiration > Date.now()) {
        // Convert PEM public key to forge public key
        const publicKey = forge.pki.publicKeyFromPem(keyData.public);

           // Convert to byte arrays
           const modulusBytes = forge.util.hexToBytes(publicKey.n.toString(16));
           const exponentBytes = forge.util.hexToBytes(publicKey.e.toString(16));
   
           // Encode to Base64 URL format
           const base64Modulus = forge.util.encode64(modulusBytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
           const base64Exponent = forge.util.encode64(exponentBytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
   
        // Add the key to the validKeys array
        validKeys.push({
          kty: 'RSA',           // Key type
          kid,                 // Key ID
          n: base64Modulus,    // Modulus
          e: base64Exponent,   // Exponent
        });
      }
      return validKeys; // Return the validKeys array
    }, []);
  }

  // Get the private key for the specified key ID
  getPrivateKey(kid) {
    return this.keys[kid]?.private; // Return the private key or undefined if not found
  }
}

// Initialize KeyManager and generate an initial key
const keyManager = new KeyManager();
keyManager.generateKey('active-key-id', 3600); // Expires in 1 hour
keyManager.generateKey('expired-key-id', -3600); // Expired key for testing

// Export the KeyManager instance
module.exports = keyManager;
