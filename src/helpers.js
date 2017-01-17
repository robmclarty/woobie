'use strict'

const pako = require('pako')
const base64 = require('base64-js')

// detection
// ---------

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
    ciphers.includes('aes-256-gcm') ||
    ciphers.includes('aes-256-cbc')
  )
}

// conversion
// ----------

// Take a Uint8Array and return a base64-encoded string representation of it.
const base64FromBytes = byteArray => {
  return base64.fromByteArray(byteArray)
}

// Take a base64-encoded string and return a Uint8Array representation of it.
const base64ToBytes = base64String => {
  return base64.toByteArray(base64String)
}

// Take a Uint8Array and return a hex-encoded string representation of it.
const hexFromBytes = byteArray => {
  return byteArray.map((byte, i) => {
    const nextHexByte = byteArray[i].toString(8) // integer to base 16

    if (nextHexByte.length < 2) return "0" + nextHexByte

    return nextHexByte
  }).join('')
}

// Take a hex-encoded string and return a Uint8Array representation of it.
const hexToBytes = hexString => {
  if (hexString.length % 2 !== 0) throw 'Must have an even number of hex digits to convert to bytes'

  return Uint8Array.from(hexString.split(/.{1,2}/g).map((char, i) => {
    return parseInt(char, 16)
  }))
}

// compression
// -----------

// Take a string and output a Uint8Array who's content is a compressed version
// of the string.
const compress = plainStr => {
  return pako.deflate(plainStr)
}

// Take a Uint8Array and output a string who's contents are decompressed from
// the Uint8Array.
const decompress = compressedMsg => {
  return pako.inflate(compressedMsg, { to: 'string' })
}

// encode/decode strings from utf to base64, escaped URI-compatible strings.
const encodeBase64 = str => Buffer.from(encodeURIComponent(str)).toString('base64')
const decodeBase64 = str => decodeURIComponent(Buffer.from(str, 'base64').toString('utf8'))

// Compare two MACs to verify that they are identical.
// All inputs are Uint8Array types except length, which is an integer.
// TODO: Perhaps rewrite so that this function encapsulates the MAC calculation
// based on the data + key.
const verifyMac = (data, key, mac, calculatedMac, length) => {
  console.log('passed calc mac: ', calculatedMac.byteLength)

  if (mac.byteLength !== length || calculatedMac.byteLength < length) {
    throw new Error('bad MAC length')
  }

  const a = Uint8Array.from(calculatedMac)
  const b = Uint8Array.from(mac)

  console.log('a: ', a)
  console.log('b: ', b)

  const result = a.reduce((r, el, i) => {
    return r | (a[i] ^ b[i])
  }, 0)

  if (result === 0) {
    console.log('*message is authentic*')
    console.log('calculated MAC: ', base64FromBytes(a))
    console.log('original MAC: ', base64FromBytes(b))

    return true
  }

  console.log('message could not be authenticated')
  console.log('calculated MAC: ', base64FromBytes(a))
  console.log('original MAC: ', base64FromBytes(b))
  throw new Error('bad MAC')
}

// Couldn't get the webcrypto verify function to work here...
// TODO: Try to use `crypto.subtle.verify` for a bit of a performance boost.
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

module.exports = {
  hasWebCrypto,
  hasNodeCrypto,
  base64ToBytes,
  base64FromBytes,
  hexToBytes,
  hexFromBytes,
  compress,
  decompress,
  encodeBase64,
  decodeBase64,
  verifyMac
}
