'use strict';

var crypto = require('crypto');
var secret_dir = require('./../config/secret');

const ALGORITHM = 'aes-256-ctr';
const ENCRYPTION_KEY = secret_dir.secret_key;
const IV_LENGHT = 16;

///////////FOR PASSWORD ENCRYPTION://////////////
var cryptoJS = require('crypto-js');
const ENCRYPTION_PASS = secret_dir.password_secret;
/////////////////////////////////////////////////

function encrypt(text) {
    let iv = crypto.randomBytes(IV_LENGHT);
    let password = new Buffer(ENCRYPTION_KEY);
    let cipher = crypto.createCipheriv(ALGORITHM, password, iv);
    let encrypted = cipher.update(text);
    
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    encrypted = encrypted.toString('hex');
    iv = iv.toString('hex');

    return iv + ":" + encrypted;
}

function decrypt(encrypted) {
    let textParts = encrypted.split(':');
    let iv = new Buffer(textParts.shift(), 'hex');
    let encryptedText = new Buffer(textParts.join(':'), 'hex');
    let password = new Buffer(ENCRYPTION_KEY);

    let decipher = crypto.createDecipheriv(ALGORITHM, password, iv);
    
    let decrypted = decipher.update(encryptedText);
    
    decrypted += decipher.final('utf8');

    return decrypted;
}

function encryptPass(text) {
    let cipher = cryptoJS.AES.encrypt(text, ENCRYPTION_PASS);
    var encrypted = cipher.toString(cryptoJS.enc.hex);

    return encrypted;
  }

function decryptPass(encrypted) {
    let decipher = cryptoJS.AES.decrypt(encrypted, ENCRYPTION_PASS);
    var decrypted = decipher.toString(cryptoJS.enc.Utf8);

    return decrypted;
  }

module.exports = { encrypt, decrypt, encryptPass, decryptPass };