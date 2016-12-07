'use strict'

const crypto = window.crypto
const base64 = require('base64-js')
const { verifyMac } = require('./helpers')

const getRandomBytes = size => {
  const array = new Uint8Array(size)

  crypto.getRandomValues(array)

  return array.buffer
}

const sign = (data, key) => {
  return crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign'])
    .then(importedKey => crypto.subtle.sign({ name: 'HMAC', hash: 'SHA-256' }, importedKey, data))
    .catch(err => console.log('error signing data: ', err))
}

// Couldn't get the webcrypto verify function to work here...
// const verifyWebcrypto = (data, key, mac) => {
//   return crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign'])
//     .then(importedKey => {
//       console.log('data: ', data)
//       console.log('mac: ', mac)
//       return crypto.subtle.verify({ name: 'HMAC', hash: 'SHA-256' }, importedKey, mac, data)
//     })
//     .then(verified => {
//       console.log('verified: ', verified)
//       if (!verified) throw new Error('MAC could not be verified. Someone might have tampered with the message.')
//     })
//     .catch(err => console.log('error verifying mac: ', err))
// }

const verify = (data, key, mac, length) => {
  return sign(data, key)
    .then(calculatedMac => verifyMac(data, key, mac, calculatedMac, length))
}

const hash = data => {
  return crypto.subtle.digest({ name: 'SHA-512' }, data)
}

const encrypt_AES_GCM = (data, key) => {
  console.log('-------------------------------------')
  console.log('encrypting with web crypto AES-GCM...')
  console.log('-------------------------------------')

  const iv = getRandomBytes(16)

  console.log('iv: ', base64.fromByteArray(iv))
  console.log('key: ', base64.fromByteArray(key))

  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
    .then(importedKey => crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, importedKey, data))
    .then(encryptedData => ({
      data: new Uint8Array(encryptedData),
      iv
    }))
    .catch(err => console.log('error encrypting message with webcrypto AES-GCM: ', err))
}

const decrypt_AES_GCM = (data, key, iv) => {
  console.log('-------------------------------------')
  console.log('decrypting with web crypto AES-GCM...')
  console.log('-------------------------------------')

  console.log('iv: ', base64.fromByteArray(iv))
  console.log('key: ', base64.fromByteArray(key))

  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt'])
    .then(importedKey => crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, importedKey, data))
    .then(decryptedData => ({
      data: decryptedData
    }))
    .catch(err => console.log('error decrypting message with webcrypto AES-GCM: ', err))
}

const encrypt_AES_CBC_HMAC = (data, key) => {
  console.log('------------------------------------------')
  console.log('encrypting with web crypto AES-CBC-HMAC...')
  console.log('------------------------------------------')

  const iv = getRandomBytes(16)

  return crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt'])
    .then(importedKey => crypto.subtle.encrypt({ name: 'AES-CBC', iv }, importedKey, data))
    .then(encryptedObj => new Uint8Array(encryptedObj))
    .then(encryptedData => Promise.all([
      encryptedData,
      sign(encryptedData, key)
    ]))
    .then(results => {
      const encryptedData = results[0]
      const mac = results[1]

      return {
        data: new Uint8Array(encryptedData),
        iv,
        mac: new Uint8Array(mac)
      }
    })
    .catch(err => console.log('error encrypting message with webcrypto aes-cbc: ', err))
}

const decrypt_AES_CBC_HMAC = (data, key, iv, mac) => {
  console.log('------------------------------------------')
  console.log('decrypting with web crypto AES-CBC-HMAC...')
  console.log('------------------------------------------')

  return verify(data, key, mac, mac.byteLength)
    .then(() => crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']))
    .then(importedKey => crypto.subtle.decrypt({ name: 'AES-CBC', iv }, importedKey, data))
    .then(decryptedData => ({
      data: decryptedData
    }))
    .catch(err => console.log('error decrypting message with webcrypto aes-cbc: ', err))
}

module.exports = {
  getRandomBytes,
  sign,
  verify,
  hash,
  encrypt_AES_GCM,
  decrypt_AES_GCM,
  encrypt_AES_CBC_HMAC,
  decrypt_AES_CBC_HMAC
}