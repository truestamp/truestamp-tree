// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

// Usage:
// You can run this sample with:
//   node example.cjs
//
// For more detailed info about speed and memory usage:
//
// macOS + Homebrew:
//   brew install gnu-time
//   gtime --verbose node example.cjs

// NOTE:
// Each of the code sections below is wrapped in `console.time()`
// and `console.timeEnd()` to give you a log output of the speed
// of execution for each section. This is not required for the
// sample to work. The size of the Merkle tree is limited by the
// Node.js heap size, and the size of your data. This has been
// tested with 10 million data elements on a laptop which is
// probably much larger than most real world data sets.

const { Tree, encodeHex } = require('../dist/index.cjs')
const crypto = require('crypto')

// Setup a hash function for the tree
// It must take a single argument of type Uint8Array and
// return a Uint8Array of the hash value. This example
// uses the Node.js crypto library.
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest()
}

// Construct some sample data. In the real world this would be
// the hash of the data you want to store in the Tree as shown
// here in the output of the map function.
console.time('data')
const ARRAY_LENGTH = 1_000
console.log('ARRAY_LENGTH', ARRAY_LENGTH)
const rawData = Array.from(Array(ARRAY_LENGTH)).map(() => Math.random())
const data = rawData.map((x) => { return sha256(x.toString()) })
console.timeEnd('data')

// Construct a Merkle Tree from the data and hash function
console.time('merkle')
const t = new Tree(data, sha256)
console.timeEnd('merkle')

// Inspect the Merkle root of the tree
console.time('root')
const r = t.root()
console.log('root', encodeHex(r))
console.timeEnd('root')

// Choose one of the original data elements to verify
const d = data[Math.floor(Math.random() * data.length)]

// Extract a Merkle inclusion proof for the data element from the tree
console.time('proof')
// const p = t.proof(d) // an alternative proof encoding, as Uint8Array
// const p = t.proofHex(d) // an alternative proof encoding, as hex string
const p = t.proofObject(d) // an alternative proof encoding, as object
console.log('proof', p)
console.timeEnd('proof')

// At any time in the future, long after the original Tree
// and its data are gone, you can verify the Merkle inclusion proof
// for any single data element. To do so, you must provide:
//
// * (r) the Merkle root of the original Tree,
// * (p) the inclusion proof in one of the supported encodings
// * (d) the data element to verify
// * the hash function used to compute the original Merkle tree
//
console.time('verify')
console.log('verified?', Tree.verify(r, p, d, sha256)) // true or false
console.timeEnd('verify')
