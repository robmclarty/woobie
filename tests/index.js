'use strict'

const test = require('tape')
const woobie = require('../src/index.js')

test('full test', t => {
  t.plan(1)

  console.log('-----------------')
  console.log('choose crypto lib')
  console.log('-----------------')

  const cryptolib = woobie.chooseCrypto()

  console.log('webcrypto: ', woobie.hasWebCrypto())
  console.log('nodecrypto: ', woobie.hasNodeCrypto())
  console.log('chosen cryptolib: ', cryptolib)

  // generate keys
  console.log('---------------------------')
  console.log('generating shared secret...')
  console.log('---------------------------')

  // Create pub/priv keys for alice
  const aliceKeys = woobie.keyPair(woobie.generateRandomBytes({
    lib: cryptolib,
    size: 32
  }))
  const alice_secretKeyStr = woobie.base64FromBytes(aliceKeys.secretKey)
  const alice_publicKeyStr = woobie.base64FromBytes(aliceKeys.publicKey)

  console.log('alice secret: ', alice_secretKeyStr)
  console.log('alice pub: ', alice_publicKeyStr)

  // Create pub/priv keys for bob
  const bobKeys = woobie.keyPair(woobie.generateRandomBytes({
    lib: cryptolib,
    size: 32
  }))
  const bob_secretKeyStr = woobie.base64FromBytes(bobKeys.secretKey)
  const bob_publicKeyStr = woobie.base64FromBytes(bobKeys.publicKey)

  console.log('bob secret: ', bob_secretKeyStr)
  console.log('bob pub: ', bob_publicKeyStr)

  // Using new buffers for public keys create shared secret from them.
  const alice_sharedSecret = woobie.sharedSecret(aliceKeys.secretKey, bobKeys.publicKey)
  const bob_sharedSecret = woobie.sharedSecret(bobKeys.secretKey, aliceKeys.publicKey)

  const alice_sharedSecretStr = woobie.base64FromBytes(alice_sharedSecret)
  const bob_sharedSecretStr = woobie.base64FromBytes(bob_sharedSecret)

  console.log('alice shared secret: ', alice_sharedSecretStr)
  console.log('bob shared secret: ', bob_sharedSecretStr)

  // encrypt/decrypt a message
  console.log('--------------')
  console.log('get plain text')
  console.log('--------------')

  const plainMsg = "It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness, it was the epoch of belief, it was the epoch of incredulity, it was the season of Light, it was the season of Darkness, it was the spring of hope, it was the winter of despair, we had everything before us, we had nothing before us, we were all going direct to Heaven, we were all going direct the other way – in short, the period was so far like the present period, that some of its noisiest authorities insisted on its being received, for good or for evil, in the superlative degree of comparison only."

  console.log('alice\'s plain text message: \n', plainMsg)

  // Encrypt, and then decrypt, using browser's WebCrypto API
  woobie.encrypt({
    lib: cryptolib,
    msg: plainMsg,
    key: alice_sharedSecretStr,
    compressed: true,
    alg: 'aes-cbc-hmac'
  })
    .then(encryptedObj => {
      console.log('encrypted message: \n', encryptedObj.data)

      return woobie.decrypt({
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
      t.equal(decryptedObj.data, plainMsg)
    })
    .catch(err => console.log('something went wrong: ', err))
})
