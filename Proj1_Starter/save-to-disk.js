const { Keychain } = require('./password-manager');
const fs = require('fs');

async function saveToDisk() {
  console.log('Creating password manager and adding passwords\n');
  
  // Initialize
  let keychain = await Keychain.init('myMasterPassword');
  
  // Add passwords
  await keychain.set('google.com', 'Password123');
  await keychain.set('facebook.com', 'Password123');
  await keychain.set('amazon.com', 'Password123');
  await keychain.set('netflix.com', 'Password123');
  
  console.log('Added 4 passwords\n');
  
  // Dump to get saved data
  let [databaseContent, checksum] = await keychain.dump();
  
  // Save to files (simulating disk storage)
  fs.writeFileSync('password_database.json', databaseContent);
  fs.writeFileSync('checksum.txt', checksum);
  
  console.log('Saved to disk:\n');
  console.log('password_database.json (main database)');
  console.log('checksum.txt (stored on USB drive)\n');
  
  // Display what was saved
  console.log('\n');
  console.log('CONTENT OF: password_database.json');
  console.log('\n');
  console.log(databaseContent);
  console.log('\n');
  
  console.log('CONTENT OF: checksum.txt');
  console.log(checksum);
  console.log('\n');
  
  // Show file sizes
  console.log(' File Information:');
  console.log('Database size:', databaseContent.length, 'bytes');
  console.log('Checksum size:', checksum.length, 'bytes\n');
  
  // Show pretty version
  console.log('\n');
  console.log('DB structure');
  console.log('\n');
  let parsed = JSON.parse(databaseContent);
  console.log(JSON.stringify(parsed, null, 2));
  console.log('\n');
  
  // Demonstrate loading
  console.log('LOADING FROM DISK:');

  
  let loadedDB = fs.readFileSync('password_database.json', 'utf8');
  let loadedChecksum = fs.readFileSync('checksum.txt', 'utf8');
  
  console.log(' Read database from file');
  console.log(' Read checksum from file');
  
  let restoredKeychain = await Keychain.load('myMasterPassword', loadedDB, loadedChecksum);
  console.log('Successfully restored keychain!\n');
  
  // Verify it works
  let password = await restoredKeychain.get('google.com');
  console.log('Testing: Retrieved password for google.com:', password);
  console.log('Database works correctly!\n');
}

saveToDisk().catch(console.error);
