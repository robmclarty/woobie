'use strict'

const pako = require('pako')
const base64 = require('base64-js')
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
    pako.deflate(msg) :
    Buffer.from(msg, 'utf8')
  const keyAsBytes = base64.toByteArray(key)
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
    data: base64.fromByteArray(encryptedData.data),
    iv: base64.fromByteArray(encryptedData.iv),
    mac: !encryptedData.mac ? '' : base64.fromByteArray(encryptedData.mac)
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
  const msgAsBytes = base64.toByteArray(msg)
  const keyAsBytes = base64.toByteArray(key)
  const ivAsBytes = base64.toByteArray(iv)
  const macAsBytes = base64.toByteArray(mac)
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
      pako.inflate(decryptedData.data, { to: 'string' }) :
      decryptedData.data.toString('utf8')
  }))
}

const fullTest = () => {
  console.log('-----------------')
  console.log('choose crypto lib')
  console.log('-----------------')

  const cryptolib = chooseCrypto()

  console.log('webcrypto: ', hasWebCrypto())
  console.log('nodecrypto: ', hasNodeCrypto())
  console.log('chosen cryptolib: ', cryptolib)

  // generate keys
  console.log('---------------------------')
  console.log('generating shared secret...')
  console.log('---------------------------')

  // Create pub/priv keys for alice
  const aliceKeys = curve25519.keyPair(generateRandomBytes({
    lib: cryptolib,
    size: 32
  }))
  const alice_secretKeyStr = base64.fromByteArray(aliceKeys.secretKey)
  const alice_publicKeyStr = base64.fromByteArray(aliceKeys.publicKey)

  console.log('alice secret: ', alice_secretKeyStr)
  console.log('alice pub: ', alice_publicKeyStr)

  // Create pub/priv keys for bob
  const bobKeys = curve25519.keyPair(generateRandomBytes({
    lib: cryptolib,
    size: 32
  }))
  const bob_secretKeyStr = base64.fromByteArray(bobKeys.secretKey)
  const bob_publicKeyStr = base64.fromByteArray(bobKeys.publicKey)

  console.log('bob secret: ', bob_secretKeyStr)
  console.log('bob pub: ', bob_publicKeyStr)

  // Using new buffers for public keys create shared secret from them.
  const alice_sharedSecret = curve25519.sharedSecret(aliceKeys.secretKey, bobKeys.publicKey)
  const bob_sharedSecret = curve25519.sharedSecret(bobKeys.secretKey, aliceKeys.publicKey)

  const alice_sharedSecretStr = base64.fromByteArray(alice_sharedSecret)
  const bob_sharedSecretStr = base64.fromByteArray(bob_sharedSecret)

  console.log('alice shared secret: ', alice_sharedSecretStr)
  console.log('bob shared secret: ', bob_sharedSecretStr)

  // encrypt/decrypt a message
  console.log('--------------')
  console.log('get plain text')
  console.log('--------------')

  const plainMsg = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way – in short, the period was so far like the present period, that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only."

  console.log('alice\'s plain text message: \n', plainMsg)

  // Encrypt, and then decrypt, using browser's WebCrypto API
  encrypt({
    lib: cryptolib,
    msg: plainMsg,
    key: alice_sharedSecretStr,
    compressed: true,
    alg: 'aes-cbc-hmac'
  })
    .then(encryptedObj => {
      console.log('encrypted message: \n', encryptedObj.data)

      return decrypt({
        lib: cryptolib,
        msg: encryptedObj.data,
        key: bob_sharedSecretStr,
        iv: encryptedObj.iv,
        mac: encryptedObj.mac,
        compressed: true,
        alg: 'aes-cbc-hmac'
      })
    })
    .then(decryptedObj => {
      console.log('bob\'s decrypted message: \n', decryptedObj.data)
    })
    .catch(err => console.log('something went wrong: ', err))
}

module.exports = {
  hasWebCrypto,
  hasNodeCrypto,
  chooseCrypto,
  encrypt,
  decrypt,
  fullTest
}
