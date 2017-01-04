'use strict'

const helpers = require('./helpers')
const crypto = helpers.hasNodeCrypto() ? require('crypto') : null

const getRandomBytes = size => {
  return crypto.randomBytes(size)
}

const sign = (data, key) => new Promise((resolve, reject) => {
  const hmac = crypto.createHmac('sha256', key)
  hmac.update(data)

  resolve(hmac.digest())
})

const verify = (data, key, mac, length) => {
  return sign(data, key)
    .then(calculatedMac => helpers.verifyMac(data, key, mac, calculatedMac, length))
}

const hash = data => new Promise((resolve, reject) => {
  const hasher = crypto.createHash('sha512')
  hasher.update(data)

  resolve(hasher.digest())
})

/**
 * Takes a plain-text buffer and returns an encrypted buffer.
 *
 * @param {Uint8Array} data - The plain text message you want to encrypt.
 * @param {Uint8Array} key - The secret key to use for encryption.
 * @return {Object} An object containing ciphertext data, iv, and mac.
 */
const encrypt_AES_GCM = (data, key) => new Promise((resolve, reject) => {
  const iv = getRandomBytes(16)
  const encryptor = crypto.createCipheriv('aes-256-gcm', key, iv)
  let encryptedData = encryptor.update(data, 'utf8')

  encryptedData = Buffer.concat([encryptedData, encryptor.final()])

  const mac = encryptor.getAuthTag()

  resolve({
    data: encryptedData,
    iv,
    mac
  })
})

/**
 * Takes a cipher-text buffer and returns a decrypted string.
 *
 * @param {Uint8Array} data - The ciphertext message you want to decrypt.
 * @param {Uint8Array} key - The secret key used to encrypt the ciphertext.
 * @param {Uint8Array} iv - The initialization vecotr used in the encryption.
 * @param {Uint8Array} mac - The authentication tag used by AES-GCM.
 * @return {Object} An object containing the decrypted data.
 */
const decrypt_AES_GCM = (data, key, iv, mac) => new Promise((resolve, reject) => {
  const decryptor = crypto.createDecipheriv('aes-256-gcm', key, iv)

  // Verify authenticity of ciphertext with mac.
  // decryptor.setAuthTag(mac)
  //
  // let decryptedData = decryptor.update(data)

  let decryptedData = decryptor.setAuthTag(mac).update(data)

  decryptedData = Buffer.concat([decryptedData, decryptor.final()])

  resolve({
    data: decryptedData
  })
})

/**
 * Takes a plain-text buffer and returns an encrypted buffer.
 *
 * @param {Uint8Array} data - The plain text message you want to encrypt.
 * @param {Uint8Array} key - The secret key to use for encryption.
 * @return {Object} An object containing ciphertext data, iv, and mac.
 */
const encrypt_AES_CBC_HMAC = (data, key) => new Promise((resolve, reject) => {
  const iv = getRandomBytes(16)
  const encryptor = crypto.createCipheriv('aes-256-cbc', key, iv)
  let encryptedData = encryptor.update(data, 'utf8')

  encryptedData = Buffer.concat([encryptedData, encryptor.final()])

  sign(encryptedData, key)
    .then(mac => resolve({
      data: encryptedData,
      iv,
      mac
    }))
    .catch(reject)
})

/**
 * Takes a cipher-text buffer and returns a decrypted string.
 *
 * @param {Uint8Array} data - The ciphertext message you want to decrypt.
 * @param {Uint8Array} key - The secret key used to encrypt the ciphertext.
 * @param {Uint8Array} iv - The initialization vecotr used in the encryption.
 * @param {Uint8Array} mac - The SHA-512 auth code used by verify().
 * @return {Object} An object containing the decrypted data.
 */
const decrypt_AES_CBC_HMAC = (data, key, iv, mac) => new Promise((resolve, reject) => {
  return verify(data, key, mac, mac.byteLength)
    .then(() => {
      const decryptor = crypto.createDecipheriv('aes-256-cbc', key, iv)
      let decryptedData = decryptor.update(data)

      decryptedData = Buffer.concat([decryptedData, decryptor.final()])

      resolve({
        data: decryptedData
      })
    })
    .catch(reject)
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
