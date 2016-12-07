'use strict'

const gulp = require('gulp')
const sourcemaps = require('gulp-sourcemaps')
const browserify = require('browserify')
const babelify = require('babelify')
const uglify = require('gulp-uglify')
const source = require('vinyl-source-stream')
const buffer = require('vinyl-buffer')

gulp.task('build', function build() {
  const browserifyOpts = {
    entries: ['./src/matryoshka.js'],
    debug: true,
    fullPaths: false
  }
  const babelifyOpts = {
    presets: ['es2015']
  }
  const stream = browserify(browserifyOpts)
    .transform(babelify.configure(babelifyOpts))

  return stream.bundle()
    .pipe(source('matryoshka.js'))
    .pipe(buffer())
    .pipe(sourcemaps.init({ loadMaps: true }))
    .pipe(uglify())
    .pipe(sourcemaps.write('.'))
    .pipe(gulp.dest('./build'))
})

gulp.task('build:test', function buildBrowserTests() {
  const browserifyOpts = {
    entries: ['./tests/browser_test.js'],
    debug: true,
    fullPaths: false
  }
  const babelifyOpts = {
    presets: ['es2015']
  }
  const stream = browserify(browserifyOpts)
    .transform(babelify.configure(babelifyOpts))

  return stream.bundle()
    .pipe(source('browser_test.js'))
    .pipe(buffer())
    .pipe(sourcemaps.init({ loadMaps: true }))
    .pipe(uglify())
    .pipe(sourcemaps.write('.'))
    .pipe(gulp.dest('./build'))
})
