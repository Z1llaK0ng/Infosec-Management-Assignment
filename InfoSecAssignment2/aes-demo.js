const crypto = require('crypto');

const note = 'Student consultation note – demonstration data only';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);

const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
const ciphertext = Buffer.concat([cipher.update(note, 'utf8'), cipher.final()]);
const tag = cipher.getAuthTag();

const decrypt = (ct) => {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
};

console.log('Ciphertext (hex):', ciphertext.toString('hex'));
console.log('Auth tag (hex):  ', tag.toString('hex'));
console.log('Decrypted:       ', decrypt(ciphertext));

const tampered = Buffer.from(ciphertext);
tampered[0] ^= 1;
try {
  console.log('Tampered result: ', decrypt(tampered));
} catch (err) {
  console.log('Tampered result:  REJECTED -', err.message);
}
