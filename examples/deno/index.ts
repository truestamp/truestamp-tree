// A simplistic Deno example of using the functions of the Tree client.

// Usage:
//   npm run build (in the root of the repository)
//   deno run examples/deno/index.ts

// Load from local lib in development
// import { Tree, encodeHex, sha512_256 } from "../../lib/index.mjs"

// Or, Load the module from deno.land/x/tree
import { Tree, encodeHex, sha512_256 } from "https://deno.land/x/truestamp_tree@v0.1.4/mod.ts";

// Or, load latest ES Module from SkyPack. You should really use a pinned URL!
// See : https://docs.skypack.dev/skypack-cdn/code/optimize-for-production
// import { Tree, encodeHex, sha512_256 } from "https://cdn.skypack.dev/@truestamp/tree@0.1.4?dts";

const ARRAY_LENGTH = 1_000
const rawData: number[] = Array.from(Array(ARRAY_LENGTH)).map(() => Math.floor(Math.random()))
const data: Uint8Array[] = rawData.map((x) => { return sha512_256(new Uint8Array([x])) })
console.log('data.length\n', data.length)

// Create a Merkle tree from the data and the hash function name.
const t = new Tree(data, 'sha512_256')

// Extract the root hash from the tree.
const r = t.root()
console.log('root\n', encodeHex(r))

// Pick a random element from the data array to verify.
const d = data[Math.floor(Math.random() * data.length)]

// Extract the inclusion proof from the tree.
const p = t.proofObject(d)
console.log('proof\n', p)

// Verify the proof.
console.log('verified?\n', Tree.verify(r, p, d, 'sha512_256')) // true or false
