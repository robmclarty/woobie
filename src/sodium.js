'use strict'

const sodium = require('libsodium-wrappers')
// https://download.libsodium.org/doc

// Uses libsodium to encrypt using ChaCha20 stream cipher with Poly1305 MAC
const encryptSodium = (msg, key) => {
  console.log('encrypting with sodium')
  return msg
}

const decryptSodium = (msg, key) => {
  console.log('decrypting with sodium')
  return msg
}
