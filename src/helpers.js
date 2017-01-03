'use strict'

const pako = require('pako')
const base64 = require('base64-js')

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
  if (mac.byteLength !== length || calculatedMac.byteLength < length) {
    throw new Error('Bad MAC length')
  }

  const a = Uint8Array.from(calculatedMac)
  const b = Uint8Array.from(mac)

  const result = a.reduce((r, el, i) => {
    return r | (a[i] ^ b[i])
  }, 0)

  if (result === 0) {
    console.log('*message is authentic*')
    console.log('calculated MAC: ', base64FromBytes(a))
    console.log('original MAC: ', base64FromBytes(b))

    return true
  }

  if (result !== 0) {
    console.log('calculated MAC: ', base64FromBytes(a))
    console.log('original MAC: ', base64FromBytes(b))
    throw new Error('bad MAC')
  }
}

module.exports = {
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
