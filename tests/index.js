'use strict'

const test = require('tape')
const woobie = require('../src/index.js')

const plainMsg = "It was the best of times, it was the worst of times, it was " +
 "the age of wisdom, it was the age of foolishness, it was the epoch of belief, " +
 "it was the epoch of incredulity, it was the season of Light, it was the season " +
 "of Darkness, it was the spring of hope, it was the winter of despair, we had " +
 "everything before us, we had nothing before us, we were all going direct to " +
 "Heaven, we were all going direct the other way – in short, the period was so " +
 "far like the present period, that some of its noisiest authorities insisted on " +
 "its being received, for good or for evil, in the superlative degree of comparison only."

const fullTest = (t, alg, cryptolib) => {
  console.log('-----------------')
  console.log('choose crypto lib')
  console.log('-----------------')

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

  console.log('alice\'s plain text message: \n', plainMsg)

  console.log('--------------------------------------')
  console.log(`encrypting with node crypto ${ alg }...`)
  console.log('--------------------------------------')

  // Encrypt, and then decrypt, using browser's WebCrypto API
  woobie.encrypt({
    lib: cryptolib,
    data: plainMsg,
    key: alice_sharedSecretStr,
    compressed: true,
    alg
  })
    .then(encryptedObj => {
      console.log('key: ', alice_sharedSecretStr)
      console.log('iv: ', encryptedObj.iv)
      console.log('mac: ', encryptedObj.mac)
      console.log('encrypted message: \n', encryptedObj.data)

      console.log('--------------------------------------')
      console.log(`decrypting with node crypto ${ alg }...`)
      console.log('--------------------------------------')

      return woobie.decrypt({
        lib: cryptolib,
        data: encryptedObj.data,
        key: bob_sharedSecretStr,
        iv: encryptedObj.iv,
        mac: encryptedObj.mac,
        compressed: true,
        alg
      })
    })
    .then(decryptedObj => {
      console.log('key: ', bob_sharedSecretStr)
      console.log('bob\'s decrypted message: \n', decryptedObj.data)
      t.equal(decryptedObj.data, plainMsg, 'decrypted message should equal original message')
    })
    .catch(err => console.log('something went wrong: ', err))
}

test('node::aes-cbc-hmac::full-test', t => {
  t.plan(1)

  fullTest(t, 'aes-cbc-hmac', woobie.CRYPTO_LIBS.NODE)
})

test('node::aes-gcm::full-test', t => {
  t.plan(1)

  fullTest(t, 'aes-gcm', woobie.CRYPTO_LIBS.NODE)
})

test('node::aes-cbc-hmac::bad-mac', t => {
  t.plan(1)

  const cryptolib = woobie.CRYPTO_LIBS.NODE
  const alg = 'aes-cbc-hmac'
  const aliceKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const bobKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const alice_sharedSecret = woobie.sharedSecret(aliceKeys.secretKey, bobKeys.publicKey)
  const bob_sharedSecret = woobie.sharedSecret(bobKeys.secretKey, aliceKeys.publicKey)

  woobie.encrypt({
    lib: cryptolib,
    data: plainMsg,
    key: woobie.base64FromBytes(alice_sharedSecret),
    compressed: true,
    alg
  })
    .then(encryptedObj => {
      const invalidMac = woobie.generateRandomBytes({ lib: cryptolib, size: 32 })

      return woobie.decrypt({
        lib: cryptolib,
        data: encryptedObj.data,
        key: woobie.base64FromBytes(bob_sharedSecret),
        iv: encryptedObj.iv,
        mac: woobie.base64FromBytes(invalidMac),
        compressed: true,
        alg
      })
    })
    .then(decryptedObj => t.notOk(decryptedObj.data))
    .catch(err => {
      t.ok(
        err.toString().includes('bad MAC'),
        'should throw error if invalid MAC'
      )
    })
})

test('node::aes-gcm::bad-mac', t => {
  t.plan(1)

  const cryptolib = woobie.CRYPTO_LIBS.NODE
  const alg = 'aes-gcm'
  const aliceKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const bobKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const alice_sharedSecret = woobie.sharedSecret(aliceKeys.secretKey, bobKeys.publicKey)
  const bob_sharedSecret = woobie.sharedSecret(bobKeys.secretKey, aliceKeys.publicKey)

  woobie.encrypt({
    lib: cryptolib,
    data: plainMsg,
    key: woobie.base64FromBytes(alice_sharedSecret),
    compressed: true,
    alg
  })
    .then(encryptedObj => {
      const invalidMac = woobie.generateRandomBytes({ lib: cryptolib, size: 32 })

      return woobie.decrypt({
        lib: cryptolib,
        data: encryptedObj.data,
        key: woobie.base64FromBytes(bob_sharedSecret),
        iv: encryptedObj.iv,
        mac: woobie.base64FromBytes(invalidMac),
        compressed: true,
        alg
      })
    })
    .then(decryptedObj => t.notOk(decryptedObj.data))
    .catch(err => {
      t.ok(
        err.toString().includes('Unsupported state or unable to authenticate data'),
        'should throw error if invalid MAC'
      )
    })
})

test('node::aes-cbc-hmac::message-tampered', t => {
  t.plan(1)

  const cryptolib = woobie.CRYPTO_LIBS.NODE
  const alg = 'aes-cbc-hmac'
  const aliceKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const bobKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const alice_sharedSecret = woobie.sharedSecret(aliceKeys.secretKey, bobKeys.publicKey)
  const bob_sharedSecret = woobie.sharedSecret(bobKeys.secretKey, aliceKeys.publicKey)

  woobie.encrypt({
    lib: cryptolib,
    data: plainMsg,
    key: woobie.base64FromBytes(alice_sharedSecret),
    compressed: true,
    alg
  })
    .then(encryptedObj => {
      // Tamper with the cipher-text by replacing all zeroes with ones.
      const tamperedMsg = encryptedObj.data.replace('0', '1')

      return woobie.decrypt({
        lib: cryptolib,
        data: tamperedMsg,
        key: woobie.base64FromBytes(bob_sharedSecret),
        iv: encryptedObj.iv,
        mac: encryptedObj.mac,
        compressed: true,
        alg
      })
    })
    .then(decryptedObj => t.notOk(decryptedObj.data))
    .catch(err => {
      t.ok(err.toString().includes('bad MAC'), 'should throw error if cipher-text is tamprered')
    })
})

test('node::aes-gcm::message-tampered', t => {
  t.plan(1)

  const cryptolib = woobie.CRYPTO_LIBS.NODE
  const alg = 'aes-gcm'
  const aliceKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const bobKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const alice_sharedSecret = woobie.sharedSecret(aliceKeys.secretKey, bobKeys.publicKey)
  const bob_sharedSecret = woobie.sharedSecret(bobKeys.secretKey, aliceKeys.publicKey)

  woobie.encrypt({
    lib: cryptolib,
    data: plainMsg,
    key: woobie.base64FromBytes(alice_sharedSecret),
    compressed: true,
    alg
  })
    .then(encryptedObj => {
      // Tamper with the cipher-text by replacing all zeroes with ones.
      const tamperedMsg = encryptedObj.data.replace('0', '1')

      return woobie.decrypt({
        lib: cryptolib,
        data: tamperedMsg,
        key: woobie.base64FromBytes(bob_sharedSecret),
        iv: encryptedObj.iv,
        mac: encryptedObj.mac,
        compressed: true,
        alg
      })
    })
    .then(decryptedObj => t.notOk(decryptedObj.data))
    .catch(err => {
      t.ok(
        err.toString().includes('Unsupported state or unable to authenticate data'),
        'should throw error if cipher-text is tamprered'
      )
    })
})

test('node::aes-gcm::invalid-shared-secret-decrypt', t => {
  t.plan(1)

  const cryptolib = woobie.CRYPTO_LIBS.NODE
  const alg = 'aes-gcm'
  const aliceKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const bobKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const alice_sharedSecret = woobie.sharedSecret(aliceKeys.secretKey, bobKeys.publicKey)
  const bob_sharedSecret = woobie.sharedSecret(bobKeys.secretKey, aliceKeys.publicKey)
  const invalid_bob_sharedSecret = woobie.generateRandomBytes({ lib: cryptolib, size: 32 })

  woobie.encrypt({
    lib: cryptolib,
    data: plainMsg,
    key: woobie.base64FromBytes(alice_sharedSecret),
    compressed: true,
    alg
  })
    .then(encryptedObj => {
      return woobie.decrypt({
        lib: cryptolib,
        data: encryptedObj.data,
        key: woobie.base64FromBytes(invalid_bob_sharedSecret),
        iv: encryptedObj.iv,
        mac: encryptedObj.mac,
        compressed: true,
        alg
      })
    })
    .then(decryptedObj => t.notOk(decryptedObj.data))
    .catch(err => {
      t.ok(
        err.toString().includes('Unsupported state or unable to authenticate data'),
        'should throw error if invalid shared secret when decrypting'
      )
    })
})

test('node::aes-gcm::invalid-shared-secret-encrypt', t => {
  t.plan(1)

  const cryptolib = woobie.CRYPTO_LIBS.NODE
  const alg = 'aes-gcm'
  const aliceKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const bobKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const alice_sharedSecret = woobie.sharedSecret(aliceKeys.secretKey, bobKeys.publicKey)
  const bob_sharedSecret = woobie.sharedSecret(bobKeys.secretKey, aliceKeys.publicKey)
  const invalid_alice_sharedSecret = woobie.generateRandomBytes({ lib: cryptolib, size: 32 })

  woobie.encrypt({
    lib: cryptolib,
    data: plainMsg,
    key: woobie.base64FromBytes(invalid_alice_sharedSecret),
    compressed: true,
    alg
  })
    .then(encryptedObj => {
      return woobie.decrypt({
        lib: cryptolib,
        data: encryptedObj.data,
        key: woobie.base64FromBytes(bob_sharedSecret),
        iv: encryptedObj.iv,
        mac: encryptedObj.mac,
        compressed: true,
        alg
      })
    })
    .then(decryptedObj => t.notOk(decryptedObj.data))
    .catch(err => {
      t.ok(
        err.toString().includes('Unsupported state or unable to authenticate data'),
        'should throw error if invalid shared secret when encrypting'
      )
    })
})

test('node::aes-cbc-hmac::invalid-shared-secret-decrypt', t => {
  t.plan(1)

  const cryptolib = woobie.CRYPTO_LIBS.NODE
  const alg = 'aes-cbc-hmac'
  const aliceKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const bobKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const alice_sharedSecret = woobie.sharedSecret(aliceKeys.secretKey, bobKeys.publicKey)
  const bob_sharedSecret = woobie.sharedSecret(bobKeys.secretKey, aliceKeys.publicKey)
  const invalid_bob_sharedSecret = woobie.generateRandomBytes({ lib: cryptolib, size: 32 })

  woobie.encrypt({
    lib: cryptolib,
    data: plainMsg,
    key: woobie.base64FromBytes(alice_sharedSecret),
    compressed: true,
    alg
  })
    .then(encryptedObj => {
      return woobie.decrypt({
        lib: cryptolib,
        data: encryptedObj.data,
        key: woobie.base64FromBytes(invalid_bob_sharedSecret),
        iv: encryptedObj.iv,
        mac: encryptedObj.mac,
        compressed: true,
        alg
      })
    })
    .then(decryptedObj => t.notOk(decryptedObj.data))
    .catch(err => {
      t.ok(
        err.toString().includes('bad MAC'),
        'should throw error if invalid shared secret when decrypting'
      )
    })
})

test('node::aes-cbc-hmac::invalid-shared-secret-encrypt', t => {
  t.plan(1)

  const cryptolib = woobie.CRYPTO_LIBS.NODE
  const alg = 'aes-cbc-hmac'
  const aliceKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const bobKeys = woobie.keyPair(woobie.generateRandomBytes({ lib: cryptolib, size: 32 }))
  const alice_sharedSecret = woobie.sharedSecret(aliceKeys.secretKey, bobKeys.publicKey)
  const bob_sharedSecret = woobie.sharedSecret(bobKeys.secretKey, aliceKeys.publicKey)
  const invalid_alice_sharedSecret = woobie.generateRandomBytes({ lib: cryptolib, size: 32 })

  woobie.encrypt({
    lib: cryptolib,
    data: plainMsg,
    key: woobie.base64FromBytes(invalid_alice_sharedSecret),
    compressed: true,
    alg
  })
    .then(encryptedObj => {
      return woobie.decrypt({
        lib: cryptolib,
        data: encryptedObj.data,
        key: woobie.base64FromBytes(bob_sharedSecret),
        iv: encryptedObj.iv,
        mac: encryptedObj.mac,
        compressed: true,
        alg
      })
    })
    .then(decryptedObj => t.notOk(decryptedObj.data))
    .catch(err => {
      t.ok(
        err.toString().includes('bad MAC'),
        'should throw error if invalid shared secret when encrypting'
      )
    })
})
