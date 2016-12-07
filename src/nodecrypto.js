'use strict'

const crypto = require('crypto')
const base64 = require('base64-js')
const { verifyMac } = require('./helpers')

const getRandomBytes = size => {
  return crypto.randomBytes(16)
}

const sign = (data, key) => new Promise((resolve, reject) => {
  const hmac = crypto.createHmac('sha256', key)
  hmac.update(data)

  resolve(hmac.digest())
})

const verify = (data, key, mac, length) => {
  return sign(data, key)
    .then(calculatedMac => verifyMac(data, key, mac, calculatedMac, length)
}

const hash = data => new Promise((resolve, reject) => {
  const hasher = crypto.createHash('sha512')
  hasher.update(data)

  resolve(hasher.digest())
})

// Takes a string or buffer and returns an encrypted buffer.
// @param {Uint8Array} msg - The plain text message you want to encrypt.
// @param {Uint8Array} key - The secret key to use for encryption.
const encrypt_AES_GCM = (data, key) => new Promise((resolve, reject) => {
  console.log('--------------------------------------')
  console.log('encrypting with node crypto AES-GCM...')
  console.log('--------------------------------------')

  const iv = getRandomBytes(16)

  console.log('iv: ', base64.fromByteArray(iv))
  console.log('key: ', base64.fromByteArray(key))

  const encryptor = crypto.createCipheriv('aes-256-gcm', key, iv)
  const encryptedData = encryptor.update(data, 'utf8')
  encryptor.final()

  const tag = encryptor.getAuthTag()

  resolve({
    data: encryptedData,
    tag,
    iv
  })
})

// Takes a string or buffer and returns a decrypted string.
// @param {Uint8Array} msg - The ciphertext message you want to decrypt.
// @param {Uint8Array} key - The secret key used to encrypt the ciphertext.
// @param {Uint8Array} iv - The initialization vecotr used in the encryption.
// @param {Uint8Array} tag - The authentication tag used by AES-GCM.
const decrypt_AES_GCM = (data, key, iv, tag) => new Promise((resolve, reject) => {
  console.log('--------------------------------------')
  console.log('decrypting with node crypto AES-GCM...')
  console.log('--------------------------------------')

  console.log('key: ', base64.fromByteArray(key))
  console.log('iv: ', base64.fromByteArray(iv))
  console.log('tag: ', base64.fromByteArray(tag))

  const decryptor = crypto.createDecipheriv('aes-256-gcm', key, iv)
  decryptor.setAuthTag(tag)

  const decryptedData = decryptor.update(data)
  decryptor.final()

  resolve({
    data: decryptedData
  })
})

const encrypt_AES_CBC_HMAC = (data, key) => new Promise((resolve, reject) => {
  console.log('-------------------------------------------')
  console.log('encrypting with node crypto AES-CBC-HMAC...')
  console.log('-------------------------------------------')

  const iv = getRandomBytes(16)

  console.log('iv: ', base64.fromByteArray(iv))
  console.log('key: ', base64.fromByteArray(key))

  const encryptor = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encryptedData = encryptor.update(data, 'utf8')
  encryptor.final()

  sign(data, key)
    .then(mac => resolve({
      data: encryptedData,
      iv,
      mac: new Uint8Array(mac)
    }))
})

const decrypt_AES_CBC_HMAC = (data, key, iv, mac) => new Promise((resolve, reject) => {
  console.log('-------------------------------------------')
  console.log('decrypting with node crypto AES-CBC-HMAC...')
  console.log('-------------------------------------------')
})

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
