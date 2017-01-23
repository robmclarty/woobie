'use strict'

import resolve from 'rollup-plugin-node-resolve'
import commonjs from 'rollup-plugin-commonjs'
import replace from 'rollup-plugin-replace'
import uglify from 'rollup-plugin-uglify'
import uglifier from 'uglify-js'
import babel from 'rollup-plugin-babel'
import babelrc from 'babelrc-rollup'

export default {
  moduleName: 'woobie',
  entry: 'src/index.js',
  dest: 'build/woobie.js',
  format: 'cjs',
  sourceMap: true,
  plugins: [
    babel({
      exclude: 'node_modules/**'
    }),
    resolve({
      jsnext: true,
      main: true,
      browser: true
    }),
    commonjs(),
    replace({
      exclude: 'node_modules/**',
      ENV: JSON.stringify(process.env.NODE_ENV || 'development')
    }),
    uglify({
      minifier: uglifier
    })
  ]
}
