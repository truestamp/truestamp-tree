// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

// Usage: run this sample with:
//   npm run build (in the root of the repository)
//   cd examples/typescript
//   npm install
//   npx ts-node index.ts

const { Tree, encodeHex, sha256 } = require('../../dist/index.cjs')

const ARRAY_LENGTH = 1_000
const rawData: number[] = Array.from(Array(ARRAY_LENGTH)).map(() => Math.floor(Math.random()))
const data: Uint8Array[] = rawData.map((x) => { return sha256(new Uint8Array([x])) })
console.log('data.length\n', data.length)

// Create a Merkle tree from the data and the hash function.
const t = new Tree(data, 'sha256')

// Extract the root hash from the tree.
const r = t.root()
console.log('root\n', encodeHex(r))

// Pick a random element from the data array to verify.
const d = data[Math.floor(Math.random() * data.length)]

// Extract the inclusion proof from the tree.
const p = t.proofObject(d)
console.log('proof\n', p)

// Verify the proof.
console.log('verified?\n', Tree.verify(r, p, d)) // true or false
