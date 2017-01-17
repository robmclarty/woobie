'use strict'

const helpers = require('./helpers')
const crypto = helpers.hasWebCrypto() ? window.crypto : null

const getRandomBytes = size => {
  return crypto.getRandomValues(new Uint8Array(size))
}

const sign = (data, key) => {
  console.log('signing...')
  console.log('data: ', helpers.base64FromBytes(data))
  console.log('key: ', helpers.base64FromBytes(key))

  return crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, true, ['sign'])
    .then(cryptoKey => {
      console.log('cryptoKey: ', cryptoKey)

      return crypto.subtle.sign({ name: 'HMAC', hash: 'SHA-256' }, cryptoKey, data)
    })
    .then(hash => {
      console.log('hash: ', helpers.base64FromBytes(hash))
      return hash
    })
    .catch(err => console.log('error signing data: ', err))
}

const verify = (data, key, mac, length) => {
  console.log('verifying...')
  console.log('mac: ', helpers.base64FromBytes(mac))

  return crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, true, ['verify'])
    .then(cryptoKey => {
      console.log('cryptoKey: ', cryptoKey)
      return crypto.subtle.verify({ name: 'HMAC', hash: 'SHA-256' }, cryptoKey, mac, data)
    })
    .then(isVerified => {
      console.log('isVerified: ', isVerified)
    })
    .catch(err => console.log('error verifying data: ', err))

  // return sign(data, key)
  //   .then(calculatedMac => {
  //     console.log('new mac: ', helpers.base64FromBytes(calculatedMac))
  //     return helpers.verifyMac(data, key, mac, calculatedMac, length)
  //   })
}

const hash = data => {
  return crypto.subtle.digest({ name: 'SHA-256' }, data)
}

/**
 * Takes a plain-text buffer and returns an encrypted buffer.
 *
 * @param {Uint8Array} data - The plain text message you want to encrypt.
 * @param {Uint8Array} key - The secret key to use for encryption.
 * @return {Object} An object containing ciphertext data, iv, and mac.
 */
const encrypt_AES_GCM = (data, key) => {
  console.log('-------------------------------------')
  console.log('encrypting with web crypto AES-GCM...')
  console.log('-------------------------------------')

  const iv = getRandomBytes(16)

  console.log('iv: ', helpers.base64FromBytes(iv))
  console.log('key: ', helpers.base64FromBytes(key))

  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
    .then(importedKey => crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, importedKey, data))
    .then(encryptedData => ({
      data: new Uint8Array(encryptedData),
      iv
    }))
}

/**
 * Takes a cipher-text buffer and returns a decrypted string.
 *
 * TODO: Separate/combine tag so webcrypto gcm is interoperable with other
 * implementations (currently not using the `tag` parameter and can only
 * decrypt messages generated with the above webcrypto encrypt function).
 *
 * @param {Uint8Array} data - The ciphertext message you want to decrypt.
 * @param {Uint8Array} key - The secret key used to encrypt the ciphertext.
 * @param {Uint8Array} iv - The initialization vecotr used in the encryption.
 * @param {Uint8Array} mac - The authentication tag used by AES-GCM.
 * @return {Object} An object containing the decrypted data.
 */
const decrypt_AES_GCM = (data, key, iv, mac) => {
  console.log('-------------------------------------')
  console.log('decrypting with web crypto AES-GCM...')
  console.log('-------------------------------------')

  console.log('iv: ', helpers.base64FromBytes(iv))
  console.log('key: ', helpers.base64FromBytes(key))

  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt'])
    .then(importedKey => crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, importedKey, data))
    .then(decryptedData => ({
      data: decryptedData
    }))
}

/**
 * Takes a plain-test buffer and returns an encrypted buffer.
 *
 * @param {Uint8Array} data - The plain text message you want to encrypt.
 * @param {Uint8Array} key - The secret key to use for encryption.
 * @return {Object} An object containing ciphertext data, iv, and mac.
 */
const encrypt_AES_CBC_HMAC = (data, key) => {
  console.log('------------------------------------------')
  console.log('encrypting with web crypto AES-CBC-HMAC...')
  console.log('------------------------------------------')

  const iv = getRandomBytes(16)
  let encryptedData = []

  console.log('iv: ', helpers.base64FromBytes(iv))
  console.log('key: ', helpers.base64FromBytes(key))

  return crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt'])
    .then(importedKey => crypto.subtle.encrypt({ name: 'AES-CBC', iv }, importedKey, data))
    .then(encryptedObj => {
      encryptedData = new Uint8Array(encryptedObj)
      return encryptedData
    })
    .then(encryptedData => sign(encryptedData, key))
    .then(mac => ({
      data: encryptedData,
      iv,
      mac: new Uint8Array(mac)
    }))
}

/**
 * Takes a cipher-text buffer and returns a decrypted string.
 *
 * @param {Uint8Array} data - The ciphertext message you want to decrypt.
 * @param {Uint8Array} key - The secret key used to encrypt the ciphertext.
 * @param {Uint8Array} iv - The initialization vecotr used in the encryption.
 * @param {Uint8Array} mac - The SHA-512 auth code used by verify().
 * @return {Object} An object containing the decrypted data.
 */
const decrypt_AES_CBC_HMAC = (data, key, iv, mac) => {
  console.log('------------------------------------------')
  console.log('decrypting with web crypto AES-CBC-HMAC...')
  console.log('------------------------------------------')

  console.log('iv: ', helpers.base64FromBytes(iv))
  console.log('key: ', helpers.base64FromBytes(key))
  console.log('mac: ', helpers.base64FromBytes(mac))

  return verify(data, key, mac, mac.byteLength)
    .then(() => crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']))
    .then(importedKey => crypto.subtle.decrypt({ name: 'AES-CBC', iv }, importedKey, data))
    .then(decryptedData => ({
      data: decryptedData
    }))
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
