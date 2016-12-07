'use strict'

const test = require('tape')
const matryoshka = require('../src/matryoshka')
const crypto = require('crypto')

test('sanity test', t => {
  t.plan(2)
  t.equal(typeof matryoshka.sanity, 'function')
  t.equal(matryoshka.sanity(), 'it worked!')
})

test('dh', t => {
  t.plan(1)

  // genreate alice's keys...
  const alice = crypto.createDiffieHellman(512)
  const alice_key = alice.generateKeys()

  // generate bob's keys...
  const bob = crypto.createDiffieHellman(alice.getPrime(), alice.getGenerator())
  const bob_key = bob.generateKeys()

  // exchange and generate shared secret...
  const alice_secret = alice.computeSecret(bob_key)
  const bob_secret = bob.computeSecret(alice_key)

  const alice_secret_str = alice_secret.toString('hex')
  const bob_secret_str = bob_secret.toString('hex')

  console.log('alice secret: ', alice_secret_str)
  console.log('bob secret: ', bob_secret_str)

  t.equal(alice_secret_str, bob_secret_str)
})

test('full test', t => {
  t.plan(1)

  matryoshka.fullTest()

  t.equal(1, 1)
})
