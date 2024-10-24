// Imports
const forge = require('node-forge');
const sqlite3 = require('sqlite3').verbose();

//to clear db file cause gradebot gets overloaded
//delete totally_not_my_privateKeys.db
//create new db file
//go to project directory in terminal
//run sqlite3 then .open totally_not_my_privateKeys.db
// enter CREATE TABLE IF NOT EXISTS keys (
  // kid INTEGER PRIMARY KEY AUTOINCREMENT,
  // key BLOB NOT NULL,
  // exp INTEGER NOT NULL )
// then run program

// KeyManager class to manage keys
class KeyManager {
  constructor() {
    this.keys = {}; // Initialize keys as an empty object

    // Create a new SQLite database
    this.db = new sqlite3.Database('totally_not_my_privateKeys.db', (err) => {
        if (err) {
            console.error("error opening database " + err.message); //error msg
        } else {
            console.log('Connected to the totally_not_my_privateKeys database.'); //debug
            // Create a new table if it does not exist
            this.db.run(
              `CREATE TABLE IF NOT EXISTS keys (
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL )`, (err) => {

                  if (err) {
                      console.error("error creating table " + err.message); //error msg
                  }
                  console.log('Table created'); //debug
                }
            )
        }
        
    });
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

    // Insert the private keys into the database
    this.db.run(
      `INSERT INTO keys (key, exp) VALUES (?, ?)`,
        [this.keys[kid].private, expiration], (err) => {
        if (err) {
            console.error("error inserting key " + err.message);
        }
        console.log(`Private Key inserted: ${kid}`); //debug ${this.keys[kid].private}
      }
    )

    // Insert the public keys into the database
    this.db.run(
      `INSERT INTO keys (key, exp) VALUES (?, ?)`,
        [this.keys[kid].public, expiration], (err) => {
        if (err) {
            console.error("error inserting key " + err.message);
        }
        console.log(`Public Key inserted: ${kid}`); //debug ${this.keys[kid].private}
      }
    )
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
          kid,                // Key ID
          n: base64Modulus,    // Modulus
          e: base64Exponent,   // Exponent
        });

        // Retrieve non-expired keys from the database.
        this.db.all(`SELECT * FROM keys WHERE exp > ?`, [Date.now()], (err) => {
          if (err) {
              console.error("error getting keys " + err.message); //error msg
          } else {
              console.log(`Public Non Expired Keys retrieved: ${kid}`); //debug
          }
        });
      } else {
          // Retrieve non-expired keys from the database.
          this.db.all(`SELECT * FROM keys WHERE exp < ?`, [Date.now()], (err) => {
            if (err) {
                console.error("error getting keys " + err.message); //error msg
            } else {
                console.log(`Public Expired Key retrieved: ${kid}`); //debug
            }
          });
      }
    // Return the validKeys array
     return validKeys;
    }, []);

  }

  

  // Get the private key for the specified key ID

  // i think kid is set to active only?
  getPrivateKey(kid) {
      if (this.keys[kid]) {
          return this.keys[kid].private; // Return the private key or undefined if not found
      } else {
        return new Promise((resolve, reject) => {
          this.db.get(`SELECT key FROM keys WHERE kid = ?`, [kid], (err, row) => {
            if (err) {
                console.error("error getting private key " + err.message); //error msg
                return reject("error");
            } 
                console.log(`get private Key retrieved: ${kid}`); //debug
                resolve(row ? row.key : undefined);
            
          });
        });
      }

      //return this.keys[kid].private; // Return the private key or undefined if not found
  }
}

// Initialize KeyManager and generate an initial key
const keyManager = new KeyManager();
keyManager.generateKey('active-key-id', 3600); // Expires in 1 hour
keyManager.generateKey('expired-key-id', -3600); // Expired key for testing

// Export the KeyManager instance
module.exports = keyManager;
