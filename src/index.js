'use strict'

const helpers = require('./helpers')
const curve25519 = require('./curve25519')
const webcrypto = require('./webcrypto')
const nodecrypto = require('./nodecrypto')

// TODO: Don't use all these switches in each function at this level. Instead
// wrap the switch in another level of abstraction from which there could be
// a global "crypto" variable which can simply be used here at this level without
// knowing the actual library that is being used.

const CRYPTO_LIBS = {
  WEBCRYPTO: 'webcrypto',
  NODE: 'node'
}

const algorithm = 'aes-256-gcm'
const dhBitDepth = 2048
const rsaBitDepth = 4096
const aesBitDepth = 256
const keySize = 32

// feature detection
// -----------------
const hasWebCrypto = () => {
  return typeof window !== 'undefined' &&
    window.crypto &&
    window.crypto.subtle &&
    typeof window.crypto.getRandomValues === 'function'
}

// TODO: do this better without including the full node lib here.
const hasNodeCrypto = () => {
  const crypto = require('crypto')

  if (typeof crypto.getCiphers !== 'function') return false

  const ciphers = crypto.getCiphers()

  return ciphers && (
    ciphers.includes(algorithm) ||
    ciphers.includes('aes-256-gcm') ||
    ciphers.includes('aes-256-cbc')
  )
}

// Return the best available crypto lib based on feature detection in order
// 1) webcrypto, 2) node crypto, 3) libsodium.
const chooseCrypto = () => {
  if (hasWebCrypto()) return CRYPTO_LIBS.WEBCRYPTO
  if (!hasWebCrypto() && hasNodeCrypto()) return CRYPTO_LIBS.NODE

  return CRYPTO_LIBS.WEBCRYPTO
}

const generateRandomBytes = ({
  lib = CRYPTO_LIBS_WEBCRYPTO,
  size = 32
}) => {
  switch(lib) {
  case CRYPTO_LIBS.NODE:
    return nodecrypto.getRandomBytes(size)
  case CRYPTO_LIBS.WEBCRYPTO:
  default:
    return webcrypto.getRandomBytes(size)
  }
}

// select crypto library
// ---------------------

// msg is a utf8 string whereas key is a base64 string.
// Format inputs as Uint8Arrays and then pass them to the selected library.
// alg can be one of 'aes-cbc-hmac' or 'aes-gcm'
const encrypt = ({
  lib = CRYPTO_LIBS.WEBCRYPTO,
  msg = '',
  key = '',
  compressed = true,
  alg = 'aes-cbc-hmac'
}) => {
  const msgAsBytes = compressed ?
    helpers.compress(msg) :
    Buffer.from(msg, 'utf8')
  const keyAsBytes = helpers.base64ToBytes(key)
  let encryptedPromise = {}

  switch (lib) {
  case CRYPTO_LIBS.NODE:
    encryptedPromise = alg === 'aes-gcm' ?
      nodecrypto.encrypt_AES_GCM(msgAsBytes, keyAsBytes) :
      nodecrypto.encrypt_AES_CBC_HMAC(msgAsBytes, keyAsBytes)
    break
  case CRYPTO_LIBS.WEBCRYPTO:
  default:
    encryptedPromise = alg == 'aes-gcm' ?
      webcrypto.encrypt_AES_GCM(msgAsBytes, keyAsBytes) :
      webcrypto.encrypt_AES_CBC_HMAC(msgAsBytes, keyAsBytes)
  }

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
  lib = CRYPTO_LIBS.WEBCRYPTO,
  msg = '',
  key = '',
  iv = '',
  mac = '',
  compressed = true,
  alg = 'aes-cbc-hmac'
}) => {
  const msgAsBytes = helpers.base64ToBytes(msg)
  const keyAsBytes = helpers.base64ToBytes(key)
  const ivAsBytes = helpers.base64ToBytes(iv)
  const macAsBytes = helpers.base64ToBytes(mac)
  let decryptedPromise = {}

  switch (lib) {
  case CRYPTO_LIBS.NODE:
    decryptedPromise = alg === 'aes-gcm' ?
      nodecrypto.decrypt_AES_GCM(msgAsBytes, keyAsBytes, ivAsBytes, macAsBytes) :
      nodecrypto.decrypt_AES_CBC_HMAC(msgAsBytes, keyAsBytes, ivAsBytes, macAsBytes)
    break
  case CRYPTO_LIBS.WEBCRYPTO:
  default:
    decryptedPromise = alg === 'aes-gcm' ?
      webcrypto.decrypt_AES_GCM(msgAsBytes, keyAsBytes, ivAsBytes, macAsBytes) :
      webcrypto.decrypt_AES_CBC_HMAC(msgAsBytes, keyAsBytes, ivAsBytes, macAsBytes)
  }

  return decryptedPromise.then(decryptedData => ({
    data: compressed ?
      helpers.decompress(decryptedData.data) :
      decryptedData.data.toString('utf8')
  }))
}

// Combine functions from curve25519 + helpers and export all together with this
// file's functions.
module.exports = Object.assign({}, helpers, curve25519, {
  hasWebCrypto,
  hasNodeCrypto,
  chooseCrypto,
  encrypt,
  decrypt,
  generateRandomBytes
})
