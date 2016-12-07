'use strict'

const pako = require('pako')
const base64 = require('base64-js')
const curve25519 = require('./curve25519')
const webcrypto = require('./webcrypto')
const nodecrypto = require('./nodecrypto')
const sodiumcrypto = require('./sodium')

const CRYPTO_LIBS = {
  WEBCRYPTO: 'webcrypto',
  NODE: 'node',
  SODIUM: 'sodium'
}

const algorithm = 'aes-256-gcm'
const dhBitDepth = 2048
const rsaBitDepth = 4096
const aesBitDepth = 256

// feature detection
// -----------------
const hasWebCrypto = () => {
  return typeof window !== 'undefined' &&
    window.crypto &&
    window.crypto.subtle &&
    typeof window.crypto.getRandomValues === 'function'
}

const hasNodeCrypto = () => {
  if (typeof crypto.getCiphers !== 'function') return false

  const ciphers = crypto.getCiphers()

  return ciphers && (
    ciphers.includes(algorithm) ||
    ciphers.includes('aes-256-gcm') ||
    ciphers.includes('aes-192-gcm')
  )
}

// Return the best available crypto lib based on feature detection in order
// 1) webcrypto, 2) node crypto, 3) libsodium.
const chooseCrypto = () => {
  if (hasWebCrypto()) return CRYPTO_LIBS.WEBCRYPTO
  if (!hasWebCrypto() && hasNodeCrypto()) return CRYPTO_LIBS.NODE

  return CRYPTO_LIBS.SODIUM
}

// select crypto library
// ---------------------

// msg is a utf8 string whereas key is a base64 string.
// Format inputs as Uint8Arrays and then pass them to the selected library.
const encrypt = ({
  lib = CRYPTO_LIBS.WEBCRYPTO,
  msg = '',
  key = '',
  compressed = true
}) => {
  const msgAsBytes = compressed ?
    pako.deflate(msg) :
    Buffer.from(msg, 'utf8')
  const keyAsBytes = base64.toByteArray(key)
  let encryptedPromise = {}

  switch (lib) {
  case CRYPTO_LIBS.NODE:
    encryptedPromise = encryptNode(msgAsBytes, keyAsBytes)
    break
  case CRYPTO_LIBS.SODIUM:
    encryptedPromise = encryptSodium(msgAsBytes, keyAsBytes)
    break
  case CRYPTO_LIBS.WEBCRYPTO:
  default:
    encryptedPromise = encryptWebcrypto_AES_GCM(msgAsBytes, keyAsBytes)
  }

  return encryptedPromise.then(encryptedData => ({
    data: base64.fromByteArray(encryptedData.data),
    iv: base64.fromByteArray(encryptedData.iv),
    tag: !encryptedData.tag ? '' : base64.fromByteArray(encryptedData.tag)
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
  tag = '',
  compressed = true
}) => {
  const msgAsBytes = base64.toByteArray(msg)
  const keyAsBytes = base64.toByteArray(key)
  const ivAsBytes = base64.toByteArray(iv)
  const tagAsBytes = base64.toByteArray(tag)
  let decryptedPromise = {}

  switch (lib) {
  case CRYPTO_LIBS.NODE:
    decryptedPromise = decryptNode(msgAsBytes, keyAsBytes, ivAsBytes, tagAsBytes)
    break
  case CRYPTO_LIBS.SODIUM:
    decryptedPromise = decryptSodium(msgAsBytes, keyAsBytes, ivAsBytes, tagAsBytes)
    break
  case CRYPTO_LIBS.WEBCRYPTO:
  default:
    decryptedPromise = decryptWebcrypto_AES_GCM(msgAsBytes, keyAsBytes, ivAsBytes)
  }

  return decryptedPromise.then(decryptedData => ({
    data: compressed ?
      pako.inflate(decryptedData.data, { to: 'string' }) :
      decryptedData.data.toString('utf8')
  }))
}

const fullTest = () => {
  console.log('webcrypto: ', hasWebCrypto())
  console.log('nodecrypto: ', hasNodeCrypto())

  // generate keys
  console.log('---------------------------')
  console.log('generating shared secret...')
  console.log('---------------------------')

  // Create pub/priv keys for alice
  const alice_secretKey = Uint8Array.from(sodium.randombytes_buf(sodium.crypto_scalarmult_SCALARBYTES))
  const alice_secretKeyStr = base64.fromByteArray(alice_secretKey)
  const alice_publicKey = sodium.crypto_scalarmult_base(alice_secretKey)
  const alice_publicKeyStr = base64.fromByteArray(alice_publicKey)

  console.log('alice secret: ', alice_secretKeyStr)
  console.log('alice pub: ', alice_publicKeyStr)

  // Create pub/priv keys for bob
  const bob_secretKey = Uint8Array.from(sodium.randombytes_buf(sodium.crypto_scalarmult_SCALARBYTES))
  const bob_secretKeyStr = base64.fromByteArray(bob_secretKey)
  const bob_publicKey = sodium.crypto_scalarmult_base(bob_secretKey)
  const bob_publicKeyStr = base64.fromByteArray(bob_publicKey)

  console.log('bob secret: ', bob_secretKeyStr)
  console.log('bob pub: ', bob_publicKeyStr)

  // Convert string keys from network back into buffers.
  const alice_publicKeyBytes = base64.toByteArray(alice_publicKeyStr)
  const bob_publicKeyBytes = base64.toByteArray(bob_publicKeyStr)

  // Using new buffers for public keys create shared secret from them.
  const alice_sharedSecret = base64.fromByteArray(sodium.crypto_scalarmult(alice_secretKey, bob_publicKeyBytes))
  const bob_sharedSecret = base64.fromByteArray(sodium.crypto_scalarmult(bob_secretKey, alice_publicKeyBytes))

  console.log('alice shared secret: ', alice_sharedSecret)
  console.log('bob shared secret: ', bob_sharedSecret)

  // ---------------------
  // encrypt/decrypt a message

  console.log('------------------------------------')
  console.log('get plain text and choose crypto lib')
  console.log('------------------------------------')

  const plainMsg = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way – in short, the period was so far like the present period, that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only."
  const cryptolib = chooseCrypto()

  console.log('cryptolib: ', cryptolib)
  console.log('plain text message: ', plainMsg)

  // Encrypt, and then decrypt, using browser's WebCrypto API
  encrypt({
    lib: cryptolib,
    msg: plainMsg,
    key: alice_sharedSecret,
    compressed: true
  })
    .then(encryptedObj => {
      console.log('encrypted message: ', encryptedObj.data)

      return decrypt({
        lib: cryptolib,
        msg: encryptedObj.data,
        key: bob_sharedSecret,
        iv: encryptedObj.iv,
        tag: encryptedObj.tag,
        compressed: true
      })
        .then(decryptedObj => {
          console.log('decrypted message: ', decryptedObj.data)
        })
    })
    .catch(err => console.log('something went wrong: ', err))
}

const fullTest_AES_CBC = () => {
  console.log('webcrypto: ', hasWebCrypto())
  console.log('nodecrypto: ', hasNodeCrypto())

  // generate keys
  console.log('---------------------------')
  console.log('generating shared secret...')
  console.log('---------------------------')

  // Create pub/priv keys for alice
  const alice_secretKey = Uint8Array.from(sodium.randombytes_buf(sodium.crypto_scalarmult_SCALARBYTES))
  const alice_secretKeyStr = base64.fromByteArray(alice_secretKey)
  const alice_publicKey = sodium.crypto_scalarmult_base(alice_secretKey)
  const alice_publicKeyStr = base64.fromByteArray(alice_publicKey)

  console.log('alice secret: ', alice_secretKeyStr)
  console.log('alice pub: ', alice_publicKeyStr)

  // Create pub/priv keys for bob
  const bob_secretKey = Uint8Array.from(sodium.randombytes_buf(sodium.crypto_scalarmult_SCALARBYTES))
  const bob_secretKeyStr = base64.fromByteArray(bob_secretKey)
  const bob_publicKey = sodium.crypto_scalarmult_base(bob_secretKey)
  const bob_publicKeyStr = base64.fromByteArray(bob_publicKey)

  console.log('bob secret: ', bob_secretKeyStr)
  console.log('bob pub: ', bob_publicKeyStr)

  // Convert string keys from network back into buffers.
  const alice_publicKeyBytes = base64.toByteArray(alice_publicKeyStr)
  const bob_publicKeyBytes = base64.toByteArray(bob_publicKeyStr)

  // Using new buffers for public keys create shared secret from them.
  const alice_sharedSecret = base64.fromByteArray(sodium.crypto_scalarmult(alice_secretKey, bob_publicKeyBytes))
  const bob_sharedSecret = base64.fromByteArray(sodium.crypto_scalarmult(bob_secretKey, alice_publicKeyBytes))

  console.log('alice shared secret: ', alice_sharedSecret)
  console.log('bob shared secret: ', bob_sharedSecret)

  // ---------------------
  // encrypt/decrypt a message

  console.log('------------------------------------')
  console.log('get plain text and choose crypto lib')
  console.log('------------------------------------')

  const plainMsg = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way – in short, the period was so far like the present period, that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only."
  const cryptolib = chooseCrypto()

  console.log('cryptolib: ', cryptolib)
  console.log('plain text message: ', plainMsg)

  // Encrypt, and then decrypt, using browser's WebCrypto API
  encryptWebcrypto_AES_CBC_HMAC(Buffer.from(plainMsg, 'utf8'), base64.toByteArray(alice_sharedSecret))
    .then(encryptedObj => {
      console.log('encrypted message: ', base64.fromByteArray(encryptedObj.data))
      console.log('encrypted mac: ', base64.fromByteArray(encryptedObj.mac))

      return decryptWebcrypto_AES_CBC_HMAC(encryptedObj.data, base64.toByteArray(bob_sharedSecret), encryptedObj.iv, encryptedObj.mac)
        .then(decryptedObj => {
          console.log('decrypted message: ', Buffer.from(decryptedObj.data).toString('utf8'))
        })
    })
    .catch(err => console.log('something went wrong: ', err))
}


module.exports = {
  sanity,
  hasWebCrypto,
  hasNodeCrypto,
  fullTest,
  fullTest_AES_CBC
}
