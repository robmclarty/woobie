'use strict'

const pako = require('pako')
const base64 = require('base64-js')

const crypto = typeof window !== 'undefined' ? window.crypto : require('crypto')
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
// TODO: return a byte array instead of a string that can simply be passed
// directly into the encryption function.
const compress = plainStr => {
  console.log('compressed msg: ', pako.deflate(plainStr, { to: 'string' }))
  return pako.deflate(plainStr)
}

// Take a buffer and output a string who's contents are decompressed from buffer.
const decompress = compressedMsg => {
  console.log('compressed msg: ', compressedMsg)
  return pako.inflate(compressedMsg, { to: 'string' })
}

// encode/decode strings from utf to base64, escaped URI-compatible strings.
const encodeBase64 = str => Buffer.from(encodeURIComponent(str)).toString('base64')
const decodeBase64 = str => decodeURIComponent(Buffer.from(str, 'base64').toString('utf8'))

// webcrypto
// ---------
const encryptWebcrypto_AES_GCM = (msg, key) => {
  console.log('-----------------------------')
  console.log('encrypting with web crypto...')
  console.log('-----------------------------')

  const iv = crypto.getRandomValues(new Uint8Array(16))

  console.log('iv: ', base64.fromByteArray(iv))
  console.log('key: ', base64.fromByteArray(key))

  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
    .then(importedKey => crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, importedKey, msg))
    .then(encryptedMsg => ({
      data: new Uint8Array(encryptedMsg),
      iv
    }))
    .catch(err => console.log('error encrypting message with webcrypto: ', err))
}

const decryptWebcrypto_AES_GCM = (msg, key, iv) => {
  console.log('-----------------------------')
  console.log('decrypting with web crypto...')
  console.log('-----------------------------')

  console.log('iv: ', base64.fromByteArray(iv))
  console.log('key: ', base64.fromByteArray(key))

  // const ivBuf = Buffer.from(iv, 'hex')
  // const keyBuf = Buffer.from(key, 'hex')
  // const msgBuf = Buffer.from(msg, 'hex')

  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt'])
    .then(importedKey => crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, importedKey, msg))
    .then(decryptedMsg => ({
      data: decryptedMsg
    }))
    .catch(err => console.log('error decrypting message with webcrypto: ', err))
}

const signWebcrypto = (data, key) => {
  return crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign'])
    .then(importedKey => crypto.subtle.sign({ name: 'HMAC', hash: 'SHA-256' }, importedKey, data))
    .catch(err => console.log('error signing data: ', err))
}

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

const verifyWebcrypto = (data, key, mac, length) => {
  return signWebcrypto(data, key)
    .then(calculatedMac => {
      if (mac.byteLength !== length || calculatedMac.byteLength < length) {
        throw new Error('Bad MAC length')
      }

      const a = new Uint8Array(calculatedMac)
      const b = new Uint8Array(mac)
      let result = 0

      for (let i = 0; i < mac.byteLength; ++i) {
        result = result | (a[i] ^ b[i])
      }

      console.log('calculated mac: ', base64.fromByteArray(a))
      console.log('original mac: ', base64.fromByteArray(b))
      console.log('result: ', result)

      if (result !== 0) {
        console.log('Our MAC: ', base64.fromByteArray(a))
        console.log('Their MAC: ', base64.fromByteArray(b))
        throw new Error('Bad MAC')
      }
    })
}

const encryptWebcrypto_AES_CBC_HMAC = (msg, key) => {
  const iv = crypto.getRandomValues(new Uint8Array(16))

  return crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt'])
    .then(importedKey => crypto.subtle.encrypt({ name: 'AES-CBC', iv }, importedKey, msg))
    .then(encryptedObj => new Uint8Array(encryptedObj))
    .then(encryptedMsg => Promise.all([
      encryptedMsg,
      signWebcrypto(encryptedMsg, key)
    ]))
    .then(results => {
      const encryptedMsg = results[0]
      const mac = results[1]

      return {
        data: new Uint8Array(encryptedMsg),
        iv,
        mac: new Uint8Array(mac)
      }
    })
    .catch(err => console.log('error encrypting message with webcrypto aes-cbc: ', err))
}

const decryptWebcrypto_AES_CBC_HMAC = (msg, key, iv, mac) => {
  return verifyWebcrypto(msg, key, mac, mac.byteLength)
    .then(() => crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt']))
    .then(importedKey => crypto.subtle.decrypt({ name: 'AES-CBC', iv }, importedKey, msg))
    .then(decryptedMsg => ({
      data: decryptedMsg
    }))
    .catch(err => console.log('error decrypting message with webcrypto aes-cbc: ', err))
}

// node crypto
// -----------

// Takes a string or buffer and returns an encrypted buffer.
// @param {Uint8Array} msg - The plain text message you want to encrypt.
// @param {Uint8Array} key - The secret key to use for encryption.
const encryptNode = (msg, key) => new Promise((resolve, reject) => {
  console.log('------------------------------')
  console.log('encrypting with node crypto...')
  console.log('------------------------------')

  const iv = crypto.randomBytes(16)

  console.log('iv: ', base64.fromByteArray(iv))
  console.log('key: ', base64.fromByteArray(key))

  const encryptor = crypto.createCipheriv(algorithm, key, iv)
  const encryptedMsg = encryptor.update(msg, 'utf8')
  encryptor.final()

  const tag = encryptor.getAuthTag()

  resolve({
    data: encryptedMsg,
    tag,
    iv
  })
})

// Takes a string or buffer and returns a decrypted string.
// @param {Uint8Array} msg - The ciphertext message you want to decrypt.
// @param {Uint8Array} key - The secret key used to encrypt the ciphertext.
// @param {Uint8Array} iv - The initialization vecotr used in the encryption.
// @param {Uint8Array} tag - The authentication tag used by AES-GCM.
const decryptNode = (msg, key, iv, tag) => new Promise((resolve, reject) => {
  console.log('------------------------------')
  console.log('decrypting with node crypto...')
  console.log('------------------------------')

  console.log('key: ', base64.fromByteArray(key))
  console.log('iv: ', base64.fromByteArray(iv))
  console.log('tag: ', base64.fromByteArray(tag))

  const decryptor = crypto.createDecipheriv(algorithm, key, iv)
  decryptor.setAuthTag(tag)

  const decryptedMsg = decryptor.update(msg)
  decryptor.final()

  resolve({
    data: decryptedMsg
  })
})

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
    encryptedPromise = encryptWebcrypto(msgAsBytes, keyAsBytes)
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
    decryptedPromise = decryptWebcrypto(msgAsBytes, keyAsBytes, ivAsBytes)
  }

  return decryptedPromise.then(decryptedData => ({
    data: compressed ?
      pako.inflate(decryptedData.data, { to: 'string' }) :
      decryptedData.data.toString('utf8')
  }))
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
