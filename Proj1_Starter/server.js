"use strict";

const express = require('express');
const path = require('path');
const { Keychain } = require('./password-manager');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static('public'));

let currentKeychain = null;
let savedData = null;
let savedChecksum = null;

// Initialize new keychain
app.post('/api/init', async (req, res) => {
  try {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ success: false, error: 'Master password is required' });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ success: false, error: 'Master password must be at least 8 characters' });
    }
    
    currentKeychain = await Keychain.init(password);
    
    res.json({ success: true, message: 'Keychain created successfully' });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Set password
app.post('/api/set', async (req, res) => {
  try {
    if (!currentKeychain) {
      return res.status(400).json({ success: false, error: 'Please create or load a keychain first' });
    }
    
    const { domain, password } = req.body;
    
    if (!domain || !password) {
      return res.status(400).json({ success: false, error: 'Domain and password are required' });
    }
    
    await currentKeychain.set(domain, password);
    
    res.json({ success: true, message: 'Password saved for ' + domain });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Get password
app.post('/api/get', async (req, res) => {
  try {
    if (!currentKeychain) {
      return res.status(400).json({ success: false, error: 'Please create or load a keychain first' });
    }
    
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ success: false, error: 'Domain is required' });
    }
    
    const password = await currentKeychain.get(domain);
    
    if (password === null) {
      res.json({ success: true, found: false, message: 'No password found for ' + domain });
    } else {
      res.json({ success: true, found: true, password: password });
    }
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Remove password
app.post('/api/remove', async (req, res) => {
  try {
    if (!currentKeychain) {
      return res.status(400).json({ success: false, error: 'Please create or load a keychain first' });
    }
    
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ success: false, error: 'Domain is required' });
    }
    
    const removed = await currentKeychain.remove(domain);
    
    res.json({ 
      success: true, 
      removed: removed,
      message: removed ? 'Password removed for ' + domain : 'No password found for ' + domain
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Dump keychain
app.get('/api/dump', async (req, res) => {
  try {
    if (!currentKeychain) {
      return res.status(400).json({ success: false, error: 'Please create or load a keychain first' });
    }
    
    const [data, checksum] = await currentKeychain.dump();
    savedData = data;
    savedChecksum = checksum;
    
    res.json({ success: true, data: data, checksum: checksum });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Load keychain
app.post('/api/load', async (req, res) => {
  try {
    const { password, data, checksum } = req.body;
    
    if (!password) {
      return res.status(400).json({ success: false, error: 'Master password is required' });
    }
    
    const loadData = data || savedData;
    const loadChecksum = checksum || savedChecksum;
    
    if (!loadData) {
      return res.status(400).json({ success: false, error: 'No saved keychain found. Please create a new one.' });
    }
    
    currentKeychain = await Keychain.load(password, loadData, loadChecksum);
    
    res.json({ success: true, message: 'Keychain loaded successfully' });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Invalid password or corrupted data' });
  }
});

// Status check
app.get('/api/status', (req, res) => {
  res.json({
    initialized: currentKeychain !== null,
    hasSavedData: savedData !== null
  });
});

// Lock keychain
app.post('/api/lock', (req, res) => {
  currentKeychain = null;
  res.json({ success: true, message: 'Keychain locked' });
});

// Generate password
app.get('/api/generate', (req, res) => {
  const length = parseInt(req.query.length) || 16;
  const includeSymbols = req.query.symbols !== 'false';
  
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  let chars = lowercase + uppercase + numbers;
  if (includeSymbols) chars += symbols;
  
  let password = '';
  const array = new Uint32Array(length);
  require('crypto').randomFillSync(array);
  
  for (let i = 0; i < length; i++) {
    password += chars[array[i] % chars.length];
  }
  
  res.json({ success: true, password: password });
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log('\n');
  console.log('  Password Manager');
  console.log('  Running at http://localhost:' + PORT);
  console.log('\n');
});
