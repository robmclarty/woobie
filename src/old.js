'use strict'

const pako = require('pako')

const crypto = window.crypto || require('crypto')
// https://nodejs.org/api/crypto.html#crypto_crypto_creatediffiehellman_prime_length_generator

const sodium = require('libsodium-wrappers')
// https://download.libsodium.org/doc

const CRYPTO_LIBS = {
  WEBCRYPTO: 'webcrypto',
  NODE: 'node',
  SODIUM: 'sodium'
}

const algorithm = 'aes-256-gcm'
const dhBitDepth = 2048
const rsaBitDepth = 4096
const aesBitDepth = 256

const sanity = () => {
  return 'it worked!'
}

// feature detection
// -----------------
const hasWebCrypto = () => {
  return window.crypto &&
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

// array buffer <-> string (from https://developers.google.com/web/updates/2012/06/How-to-convert-ArrayBuffer-to-and-from-String)
// -----------------------
const ab2str = buf => {
  return String.fromCharCode.apply(null, new Uint16Array(buf))
}

const str2ab = str => {
  const buf = new ArrayBuffer(str.length * 2) // 2 bytes for each char
  const bufView = new Uint16Array(buf)

  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i)
  }

  return buf
}

// hex to byte array
const byteArrayToHexString = byteArray => {
  return byteArray.map((byte, i) => {
    const nextHexByte = byteArray[i].toString(16) // integer to base 16

    if (nextHexByte.length < 2) return "0" + nextHexByte

    return nextHexByte
  }).join('')
}

const hexStringToByteArray = hexString => {
  if (hexString.length % 2 !== 0) throw 'Must have an even number of hex digits to convert to bytes'

  return Uint8Array.from(hexString.split(/.{1,2}/g).map((char, i) => {
    return parseInt(char, 16)
  }))
}

// compression
// -----------

// Take a string and output a buffer who's content is a compressed version of string.
const compress = (plainStr) => {
  return pako.deflate(plainStr, { to: 'string' })
}

// Take a buffer and output a string who's contents are decompressed from buffer.
const decompress = (compressedMsg) => {
  return pako.inflate(compressedMsg, { to: 'string' })
}

// webcrypto
// ---------
const encryptWebcrypto = (msg, key) => {
  console.log('-----------------------------')
  console.log('encrypting with web crypto...')
  console.log('-----------------------------')

  const iv = crypto.getRandomValues(new Uint8Array(16))
  console.log('iv: ', sodium.to_hex(iv))

  //const msgBuf = sodium.from_string(msg)
  const msgBuf = Buffer.from(msg, 'utf8')

  console.log('key: ', key)
  const keyBuf = Buffer.from(key, 'hex')

  return crypto.subtle.importKey('raw', keyBuf, { name: 'AES-GCM' }, false, ['encrypt'])
    .then(importedKey => crypto.subtle.encrypt({ name: 'AES-GCM', iv }, importedKey, msgBuf))
    .then(encryptedMsg => {
      const arrayMsg = new Uint8Array(encryptedMsg)

      return {
        data: sodium.to_hex(arrayMsg),
        iv: sodium.to_hex(iv)
      }
    })
    .catch(err => console.log('error encrypting message: ', err))
}

const decryptWebcrypto = (msg, key, iv) => {
  console.log('-----------------------------')
  console.log('decrypting with web crypto...')
  console.log('-----------------------------')

  console.log('iv: ', iv)
  const ivBuf = Buffer.from(iv, 'hex')

  console.log('key: ', key)
  const keyBuf = Buffer.from(key, 'hex')
  const msgBuf = Buffer.from(msg, 'hex')

  return crypto.subtle.importKey('raw', keyBuf, { name: 'AES-GCM' }, false, ['decrypt'])
    .then(importedKey => crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivBuf }, importedKey, msgBuf))
    .then(decryptedMsg => ({
      data: sodium.to_string(decryptedMsg)
    }))
    .catch(err => console.log('error decrypting message: ', err))
}

// node crypto
// -----------

// Takes a string or buffer and returns an encrypted buffer.
const encryptNode = (msg, key) => {
  console.log('encrypting with node crypto')
  const iv = crypto.randomBytes(16).toString('hex')
  const encryptor = crypto.createCipheriv(algorithm, key, iv)

  let encryptedMsg = encryptor.update(msg, 'utf8', 'hex')
  encryptedMsg += encryptor.final('hex')

  const tag = encryptor.getAuthTag().toString('hex')

  return {
    content: encryptedMsg,
    tag,
    iv
  }
}

// Takes a string or buffer and returns a decrypted string.
const decryptNode = (msg, key, iv, tag) => {
  console.log('decrypting with node crypto')

  console.log('key: ', sodium.to_hex(key))
  console.log('iv: ', iv)
  console.log('tag: ', tag)

  const decryptor = crypto.createDecipheriv(algorithm, key, iv)
  decryptor.setAuthTag(Buffer.from(tag, 'hex'))

  let decryptedMsg = decryptor.update(msg, 'hex', 'utf8')
  decryptedMsg += decryptor.final('utf8')

  return decryptedMsg
}

// sodium
// ------

// Uses libsodium to encrypt using ChaCha20 stream cipher with Poly1305 MAC
const encryptSodium = (msg, key) => {
  console.log('encrypting with sodium')
  return msg
}

const decryptSodium = (msg, key) => {
  console.log('decrypting with sodium')
  return msg
}

// select crypto library
// ---------------------
const encrypt = (msg = '', key = '', method = CRYPTO_LIBS.WEBCRYPTO) => {
  switch (method) {
  case CRYPTO_LIBS.NODE:
    return encryptNode(msg, key)
  case CRYPTO_LIBS.SODIUM:
    return encryptSodium(msg, key)
  case CRYPTO_LIBS.WEBCRYPTO:
  default:
    return encryptWebcrypto(msg, key)
  }
}

const decrypt = (msg = '', key = '', iv = '', tag = '', method = CRYPTO_LIBS.WEBCRYPTO) => {
  switch (method) {
  case CRYPTO_LIBS.NODE:
    return decryptNode(msg, key, iv, tag)
  case CRYPTO_LIBS.SODIUM:
    return decryptSodium(msg, key, iv, tag)
  case CRYPTO_LIBS.WEBCRYPTO:
  default:
    return decryptWebcrypto(msg, key, iv)
  }
}

// combos
// ------
const encryptCompressed = (msg = '', key = '', method = CRYPTO_LIBS.WEBCRYPTO) => {
  return encrypt(compress(msg), key, method)
  // console.log('compressed message: ', compress(msg))
  //
  // return compress(msg)

  //return encrypt(compress(msg), key, method)
}

const decryptCompressed = (msg = '', key = '', iv = '', tag = '', method = CRYPTO_LIBS.WEBCRYPTO) => {
  return decompress(decrypt(msg, key, iv, tag, method))

  // return decompress(msg)

  //return decrypt(msg, key, iv, tag, method)
}

// https://nodejs.org/api/crypto.html#crypto_class_diffiehellman
const dhKeyExchange = () => {
  // the prime is chared by everyone
  const server = crypto.createDiffieHellman(dhBitDepth)
  const prime = server.getPrime()

  // sharing secret key on a pair
  const alice = crypto.createDiffieHellman(prime)
  alice.generateKeys()
  const alicePub = alice.getPublicKey()

  const bob = crypto.createDiffieHellman(prime)
  bob.genreateKeys()
  const bobPub = bob.getPublicKey()

  const bobAliceSecret = bob.computeSecret(alicePub)
  const aliceBobSecret = alice.computeSecret(bobPub)

  // shared secret with 3rd person
  const carol = crypto.createDiffieHellman(alicePub)
  carol.genreateKeys()
  const carolPub = carol.getPublicKey()

  const carolAliceSecret = carol.computeSecret(alicePub)
  const aliceCarolSecret = alice.computeSecret(carolPub)
}

const testKeyExchangeNodeCrypto = () => {
  // genreate alice's keys...
  const alice = crypto.createDiffieHellman(2048)
  const alice_key = alice.generateKeys()

  // generate bob's keys...
  const bob = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator())
  const bob_key = bob.generateKeys()

  // exchange and generate shared secret...
  const alice_secret = alice.computeSecret(bob_key)
  const bob_secret = bob.computeSecret(alice_key)

  const alice_sharedSecret = alice_secret.toString('hex')
  const bob_sharedSecret = bob_secret.toString('hex')

  console.log('alice secret: ', alice_sharedSecret)
  console.log('bob secret: ', bob_sharedSecret)
}

// https://www.npmjs.com/package/libsodium
const basicEncrypt = () => {
  const secret = Buffer.from('724b092810ec86d7e35c9d067702b31ef90bc43a7b598626749914d6a3e033ed', 'hex')

  const encrypt = message => {
    const nonce = Buffer.from(sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES))
    const buf = Buffer.from(message)

    return Buffer.concat([nonce, Buffer.from(sodium.crypto_secretbox_easy(buf, nonce, secret))])
  }

  const decrypt = encryptedBuffer => {
    const nonce = encryptedBuffer.slice(0, sodium.crypto_box_NONCEBYTES)
    const encryptedMessage = encryptedBuffer.slice(sodium.crypto_box_NONCEBYTES)

    return sodium.crypto_secretbox_open_easy(encryptedMessage, nonce, secret, 'text')
  }

  const msg = 'This is my amazing test message that will never be guessed.'

  console.log('original message: ', msg)

  const encryptedBuf = encrypt(msg)

  console.log('encrypted buf: ', encryptedBuf)

  const decryptedMsg = decrypt(encryptedBuf)

  console.log('decrypted msg: ', decryptedMsg)
}

const ecdhKeyExchange25519 = () => {
  // ---------------------
  // generate keys

  // Create pub/priv keys for alice
  const alice_secretKey = Buffer.from(sodium.randombytes_buf(sodium.crypto_scalarmult_SCALARBYTES))
  const alice_publicKey = sodium.crypto_scalarmult_base(alice_secretKey)
  const alice_publicKeyStr = sodium.to_hex(alice_publicKey)

  console.log('alice pub: ', alice_publicKeyStr)

  // Create pub/priv keys for bob
  const bob_secretKey = Buffer.from(sodium.randombytes_buf(sodium.crypto_scalarmult_SCALARBYTES))
  const bob_publicKey = sodium.crypto_scalarmult_base(bob_secretKey)
  const bob_publicKeyStr = sodium.to_hex(bob_publicKey)

  console.log('bob pub: ', bob_publicKeyStr)

  // Convert string keys from network back into buffers.
  const alice_publicKeyFromStr = sodium.from_hex(alice_publicKeyStr)
  const bob_publicKeyFromStr = sodium.from_hex(bob_publicKeyStr)

  // Using new buffers for public keys create shared secret from them.
  const alice_sharedSecret = sodium.crypto_scalarmult(alice_secretKey, bob_publicKeyFromStr)
  const bob_sharedSecret = sodium.crypto_scalarmult(bob_secretKey, alice_publicKeyFromStr)

  console.log('alice key: ', sodium.to_hex(alice_sharedSecret))
  console.log('bob key: ', sodium.to_hex(bob_sharedSecret))

  // ---------------------
  // encrypt/decrypt a message

  const plainMsg = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way – in short, the period was so far like the present period, that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only."
  const cryptolib = chooseCrypto()

  console.log('cryptolib: ', cryptolib)
  console.log('before: ', plainMsg)

  // const compressedThing = compress(plainMsg)
  // console.log('compressed thing: ', compressedThing)
  //
  // //const encryptedThing = encryptNode(compressedThing, alice_sharedSecret)
  // const encryptedThing = encrypt(compressedThing, alice_sharedSecret, cryptolib)
  // console.log('encrypted thing: ', encryptedThing)
  //
  // //const decryptedThing = decryptNode(encryptedThing.content, bob_sharedSecret, encryptedThing.iv, encryptedThing.tag)
  // const decryptedThing = decrypt(encryptedThing.content, bob_sharedSecret, encryptedThing.iv, encryptedThing.tag, cryptolib)
  // console.log('decrypted thing: ', decryptedThing)
  //
  // const decompressedThing = decompress(decryptedThing)
  // console.log('decompressed thing: ', decompressedThing)


  const encryptedMsg = encryptCompressed(plainMsg, alice_sharedSecret, cryptolib)
  console.log('encrypted msg: ', encryptedMsg)

  const decryptedMsg = decryptCompressed(encryptedMsg.content, bob_sharedSecret, encryptedMsg.iv, encryptedMsg.tag, cryptolib)
  console.log('decrypted msg: ', decryptedMsg)
}

const fullTest = () => {
  // ---------------------
  // generate keys
  console.log('---------------------------')
  console.log('generating shared secret...')
  console.log('---------------------------')

  // Create pub/priv keys for alice
  const alice_secretKey = Buffer.from(sodium.randombytes_buf(sodium.crypto_scalarmult_SCALARBYTES))
  const alice_publicKey = sodium.crypto_scalarmult_base(alice_secretKey)
  const alice_publicKeyStr = sodium.to_hex(alice_publicKey)

  console.log('alice pub: ', alice_publicKeyStr)

  // Create pub/priv keys for bob
  const bob_secretKey = Buffer.from(sodium.randombytes_buf(sodium.crypto_scalarmult_SCALARBYTES))
  const bob_publicKey = sodium.crypto_scalarmult_base(bob_secretKey)
  const bob_publicKeyStr = sodium.to_hex(bob_publicKey)

  console.log('bob pub: ', bob_publicKeyStr)

  // Convert string keys from network back into buffers.
  const alice_publicKeyFromStr = sodium.from_hex(alice_publicKeyStr)
  const bob_publicKeyFromStr = sodium.from_hex(bob_publicKeyStr)

  // Using new buffers for public keys create shared secret from them.
  const alice_sharedSecret = sodium.crypto_scalarmult(alice_secretKey, bob_publicKeyFromStr)
  const bob_sharedSecret = sodium.crypto_scalarmult(bob_secretKey, alice_publicKeyFromStr)

  console.log('alice key: ', sodium.to_hex(alice_sharedSecret))
  console.log('bob key: ', sodium.to_hex(bob_sharedSecret))

  // ---------------------
  // encrypt/decrypt a message

  console.log('get plain text and choose crypto lib')

  const plainMsg = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way – in short, the period was so far like the present period, that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only."
  const cryptolib = chooseCrypto()

  console.log('cryptolib: ', cryptolib)
  console.log('plain text message: ', plainMsg)

  // const compressedThing = compress(plainMsg)
  // console.log('compressed thing: ', compressedThing)
  //
  // //const encryptedThing = encryptNode(compressedThing, alice_sharedSecret)
  // const encryptedThing = encrypt(compressedThing, alice_sharedSecret, cryptolib)
  // console.log('encrypted thing: ', encryptedThing)
  //
  // //const decryptedThing = decryptNode(encryptedThing.content, bob_sharedSecret, encryptedThing.iv, encryptedThing.tag)
  // const decryptedThing = decrypt(encryptedThing.content, bob_sharedSecret, encryptedThing.iv, encryptedThing.tag, cryptolib)
  // console.log('decrypted thing: ', decryptedThing)
  //
  // const decompressedThing = decompress(decryptedThing)
  // console.log('decompressed thing: ', decompressedThing)


  encrypt(plainMsg, sodium.to_hex(alice_sharedSecret), cryptolib)
    .then(encryptedObj => {
      console.log('encrypted message: ', encryptedObj.data)
      return decrypt(encryptedObj.data, sodium.to_hex(bob_sharedSecret), encryptedObj.iv, '', cryptolib)
        .then(decryptedObj => {
          console.log('decrypted message: ', decryptedObj.data)
        })
    })
    .catch(err => console.log('something went wrong: ', err))
}


module.exports = {
  sanity,
  hasWebCrypto,
  hasNodeCrypto,
  testKeyExchangeNodeCrypto,
  ecdhKeyExchange25519,
  fullTest
}
