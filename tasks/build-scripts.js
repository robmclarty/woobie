'use strict'

const gulp = require('gulp')
const uglify = require('gulp-uglify')
const browserify = require('browserify')
const babelify = require('babelify')
const source = require('vinyl-source-stream')
const buffer = require('vinyl-buffer')

// Concatenate all app JS files, parse JSX and ES6 using Babel, write
// sourcemaps, use browserify for CommonJS and output to
// 'public/js/application.js' as ES5.
gulp.task('build:scripts', function () {
  const browserifyOpts = {
    entries: ['./src'],
    debug: true,
    fullPaths: false
  }
  const babelOpts = {
    presets: ['es2015'],
    plugins: ['babel-plugin-transform-object-rest-spread']
  }
  const stream = browserify(browserifyOpts)
    .transform(babelify.configure(babelOpts))

  return stream.bundle()
    .pipe(source('woobie.js'))
    .pipe(buffer())
    .pipe(uglify())
    .pipe(gulp.dest('./build'))
})
