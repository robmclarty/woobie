'use strict'

const test = require('tape')
const matryoshka = require('../src/matryoshka')

test('sanity test', t => {
  t.plan(2)
  t.equal(typeof matryoshka.sanity, 'function')
  t.equal(matryoshka.sanity(), 'it worked!')
})
