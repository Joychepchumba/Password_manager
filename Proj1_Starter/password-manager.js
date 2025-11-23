"use strict";
/****
    * GROUP MEMBERS:
    *167026 : Victor Kimotho
    *167998: Kristein Mwaura
    *152502 : Joy Kipkemboi

*****/
/********* External Imports ********/
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/
const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor() {
    this.data = {
      kvs: {}, //stores the HMAC domain
      salt: null  // stored Random salt for PKBDF2
    };
    this.secrets = {
      hmacKey: null, // Key used to hash domain names
      aesKey: null // Key used to encrypt passwords
    };
  }

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
   // STEP 3: Convert password string to a CryptoKey object
  static async init(password) {
    let keychain = new Keychain();
    keychain.data.salt = encodeBuffer(getRandomBytes(16));
    let passwordKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    console.log("Imported password as CryptoKey");
    
    // STEP 4: Run PBKDF2 to get a strong master key
    let masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: decodeBuffer(keychain.data.salt),        
        iterations: PBKDF2_ITERATIONS,   
        hash: "SHA-256"                  
      },
      passwordKey,                       
      {                                  
        name: "HMAC",
        hash: "SHA-256",
        length: 256                      
      },
      true,                              
      ["sign"]                           
    );
    
    console.log("Derived master key with PBKDF2");
    
    // STEP 5: Use HMAC with master key to derive HMAC sub-key
    let hmacKeyMaterial = await subtle.sign(
      "HMAC",
      masterKey,
      stringToBuffer("hmac-key")  
    );
    
    // Convert the raw bytes into a proper HMAC key
    keychain.secrets.hmacKey = await subtle.importKey(
      "raw",
      hmacKeyMaterial,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]  // Can sign and verify
    );
    
    console.log("Derived HMAC key");
    
    // STEP 6: Derive AES key using a DIFFERENT constant
    let aesKeyMaterial = await subtle.sign(
      "HMAC",
      masterKey,
      stringToBuffer("aes-key")  // Different string = different key!
    );
    
    // AES-256 needs exactly 32 bytes (256 bits)
    keychain.secrets.aesKey = await subtle.importKey(
      "raw",
      aesKeyMaterial.slice(0, 32),  // Take first 32 bytes
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]  // Can encrypt and decrypt
    );
    
    console.log("Derived AES key");
   
    keychain.data.passwordCheck = encodeBuffer(
      await subtle.sign(
      "HMAC",
      keychain.secrets.hmacKey,
      stringToBuffer("password-check-verification")
    )
  );
    return keychain;
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    // STEP 1: Verify checksum if provided (rollback attack protection)
    if (trustedDataCheck !== undefined) {
      // Compute SHA-256 of the provided representation
      let hashBuffer = await subtle.digest(
        "SHA-256",
        stringToBuffer(repr)
      );
      let computedChecksum = encodeBuffer(hashBuffer);
      
      // Compare with trusted checksum
      if (computedChecksum !== trustedDataCheck) {
        throw new Error("Integrity check failed - rollback attack detected");
      }
    }
    
    // STEP 2: Parse JSON to get the data
    let data = JSON.parse(repr);
    let passwordKey = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    
    // Derive master key with PBKDF2
    let masterKey = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: decodeBuffer(data.salt),  //Using saved salt!
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      passwordKey,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      true,
      ["sign"]
    );
    
    // STEP 4: Derive HMAC key (same as init)
    let hmacKeyMaterial = await subtle.sign(
      "HMAC",
      masterKey,
      stringToBuffer("hmac-key")
    );
    
    let hmacKey = await subtle.importKey(
      "raw",
      hmacKeyMaterial,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
    
    // Derive AES key (same as init)
    let aesKeyMaterial = await subtle.sign(
      "HMAC",
      masterKey,
      stringToBuffer("aes-key")
    );
    
    let aesKey = await subtle.importKey(
      "raw",
      aesKeyMaterial.slice(0, 32),
      "AES-GCM",
      false,
      ["encrypt", "decrypt"]
    );
    
    // STEP 5: Create new Keychain and populate it
    let keychain = new Keychain();
    
    // Restore the data (salt and kvs)
    keychain.data = data;
    
    
    keychain.secrets.hmacKey = hmacKey;
    keychain.secrets.aesKey = aesKey;
    if (keychain.data.passwordCheck) {
      let computedCheck = encodeBuffer(
         await subtle.sign(
          "HMAC",
          keychain.secrets.hmacKey,
          stringToBuffer("password-check-verification")
         ) 
      );
  
      if (computedCheck !== keychain.data.passwordCheck) {
        throw new Error("Invalid password");
      }
    }

    
    return keychain;
  }

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
    // STEP 1: Serialize this.data to JSON string
    // this.data contains: { kvs: {...}, salt: [...] }
    let representation = JSON.stringify(this.data);
    
    // STEP 2: Compute SHA-256 hash of the entire serialization
    let hashBuffer = await subtle.digest(
      "SHA-256",
      stringToBuffer(representation)  // Hash the JSON string
    );
    
    // Convert hash buffer to Base64 string
    let checksum = encodeBuffer(hashBuffer);
    return [representation, checksum]; // returns the array [json_string, checksum]
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) { // This fnc helps user retrieve the password and use for a website
    // STEP 1: Hash the domain to get the storage key
    // (Same process as in set!)
    let domainHashBuffer = await subtle.sign(
      "HMAC",
      this.secrets.hmacKey,
      stringToBuffer(name)
    );
    let domainKey = encodeBuffer(domainHashBuffer);
    
    if (!(domainKey in this.data.kvs)) {
      return null;  // Domain doesn't exist    }
    }      
    // STEP 3: Get the stored record
    let record = this.data.kvs[domainKey];
    
    // STEP 4: Decrypt
    try {
      let decryptedBuffer = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: decodeBuffer(record.iv), // Decodes base64 to buffer
          additionalData: stringToBuffer(name) // Must be the same as the one used when we were encrypting else password retreval fails, this is the one that prevents say swapping google.com with evil.com
        },
        this.secrets.aesKey,
        decodeBuffer(record.ciphertext)
      );
      
      // STEP 5: Convert buffer to string and remove padding
      let paddedPassword = bufferToString(decryptedBuffer); // This removes null characters from the end 
      
      // Remove null characters from the end
      let password = paddedPassword.replace(/\0+$/, '');
      return password;
      
    } catch (e) {
      throw new Error("Integrity check failed - possible tampering detected");
    }
  }

  /** 
  *Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) { // This fnc, helps store the hashed passwords and domain in  the local drive
    // STEP 1: Pad the password to 64 characters
    // This hides the real password length
    let paddedPassword = value.padEnd(MAX_PASSWORD_LENGTH, '\0');
    let domainHashBuffer = await subtle.sign(
      "HMAC",
      this.secrets.hmacKey,      // Use our HMAC key
      stringToBuffer(name)       // Hash the domain name
    );
    
    // Convert buffer to Base64 string (so it can be a JavaScript object key)
    let domainKey = encodeBuffer(domainHashBuffer);
    //STEP 3: Generate random IV for AES-GCM
    // AES-GCM requires 12 bytes (96 bits) for IV
    let iv = getRandomBytes(12);
    
    let ciphertext = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        additionalData: stringToBuffer(name)
      },
      this.secrets.aesKey,           // Our AES key
      stringToBuffer(paddedPassword) // The padded password
    );
    this.data.kvs[domainKey] = {
      iv: encodeBuffer(iv),
      ciphertext: encodeBuffer(ciphertext)
    };
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    // Hash domain to get storage key
    let domainHashBuffer = await subtle.sign(
      "HMAC",
      this.secrets.hmacKey,
      stringToBuffer(name)
    );
    let domainKey = encodeBuffer(domainHashBuffer);
    if (domainKey in this.data.kvs) {
      delete this.data.kvs[domainKey];
      return true;
    }
    return false;
  }
}

module.exports = { Keychain };
