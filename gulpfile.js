'use strict'

const gulp = require('gulp')
const argv = require('yargs').argv
const requireDir = require('require-dir')

// Require all tasks.
requireDir('./tasks', { recurse: true })

function setProductionEnv(done) {
  process.env.NODE_ENV = 'production'
  done()
}
