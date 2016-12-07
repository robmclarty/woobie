'use strict'

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
const byteArray2Hex = byteArray => {
  return byteArray.map((byte, i) => {
    const nextHexByte = byteArray[i].toString(16) // integer to base 16

    if (nextHexByte.length < 2) return "0" + nextHexByte

    return nextHexByte
  }).join('')
}

const hex2ByteArray = hexString => {
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

// All inputs are Uint8Array types except length, which is an integer.
const verifyMac = (data, key, mac, calculatedMac, length) => {
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

  return true
}

module.exports = {
  str2ab,
  ab2str,
  compress,
  decompress,
  encodeBase64,
  decodeBase64,
  verifyMac
}
