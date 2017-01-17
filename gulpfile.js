'use strict'

const gulp = require('gulp')
const argv = require('yargs').argv
const requireDir = require('require-dir')

// Require all tasks.
requireDir('./tasks', { recurse: true })

function setProductionEnv(done) {
  process.env.NODE_ENV = 'production'
  return done()
}

// Build for production (include minification, revs, etc.).
const buildProduction = gulp.series(
  'clean',
  setProductionEnv,
  gulp.parallel('build:scripts')
)

// Build for development (include React dev, no revs, no minification, etc.).
const buildDevelopment = gulp.series(
  'clean',
  gulp.parallel('build:scripts')
)

// Choose between building for dev or production based on --production flag.
function build(done) {
  if (argv.production) {
    buildProduction()
  } else {
    buildDevelopment()
  }

  return done()
}
build.description = 'Build all the things!'
build.flags = {
  '--production': 'Builds in production mode (minification, revs, etc.).'
}
gulp.task(build)

gulp.task('default', gulp.series(build))
