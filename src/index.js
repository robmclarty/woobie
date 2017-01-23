'use strict'

const helpers = require('./helpers')
const curve25519 = require('./curve25519')
const webcrypto = require('./webcrypto')

const generateRandomBytes = ({ size = 32 }) => webcrypto.getRandomBytes(size)

// select crypto library
// ---------------------

// msg is a utf8 string whereas key is a base64 string.
// Format inputs as Uint8Arrays and then pass them to the selected library.
// alg can be one of 'aes-cbc-hmac' or 'aes-gcm'
const encrypt = ({
  data = '',
  key = '',
  compressed = true,
  alg = 'aes-cbc-hmac'
}) => {
  const dataAsBytes = compressed ?
    helpers.compress(data) :
    Buffer.from(data, 'utf8')
  const keyAsBytes = helpers.base64ToBytes(key)
  const encryptedPromise = alg == 'aes-gcm' ?
    webcrypto.encrypt_AES_GCM(msgAsBytes, keyAsBytes) :
    webcrypto.encrypt_AES_CBC_HMAC(msgAsBytes, keyAsBytes)

  return encryptedPromise.then(encryptedData => ({
    data: helpers.base64FromBytes(encryptedData.data),
    iv: helpers.base64FromBytes(encryptedData.iv),
    mac: !encryptedData.mac ? '' : helpers.base64FromBytes(encryptedData.mac)
  }))
}

// msg, key, iv, and tag inputs are base64 strings.
// Format inputs as Uint8Arrays and then pass them to the selected library and
// return a decrypted, decompressed, utf8 string.
const decrypt = ({
  data = '',
  key = '',
  iv = '',
  mac = '',
  compressed = true,
  alg = 'aes-cbc-hmac'
}) => {
  const dataAsBytes = helpers.base64ToBytes(data)
  const keyAsBytes = helpers.base64ToBytes(key)
  const ivAsBytes = helpers.base64ToBytes(iv)
  const macAsBytes = helpers.base64ToBytes(mac)
  const decryptedPromise = alg === 'aes-gcm' ?
    webcrypto.decrypt_AES_GCM(dataAsBytes, keyAsBytes, ivAsBytes, macAsBytes) :
    webcrypto.decrypt_AES_CBC_HMAC(dataAsBytes, keyAsBytes, ivAsBytes, macAsBytes)

  return decryptedPromise.then(decryptedData => ({
    data: compressed ?
      helpers.decompress(decryptedData.data) :
      decryptedData.data.toString('utf8')
  }))
}

// Combine functions from curve25519 + helpers and export all together with this
// file's functions.
module.exports = Object.assign({}, helpers, curve25519, {
  encrypt,
  decrypt,
  generateRandomBytes
})
