# @truestamp/tree

This library provides a TypeScript/JavaScript API for creating Merkle trees, and validating Merkle inclusion proofs.

Data provided to create the tree is required to already be in binary form (`Uint8Array`) and all
internal operations are performed on binary data.

The library provides several encodings for Merkle inclusion proofs, any one of which is acceptable for validation.

This library doesn't hash original data, you have to provide hashed (or arbitrary binary data of fixed size). All SHA2 and SHA3 common hash functions, implemented in pure TypeScript, are exported for your convenience and are the same hash functions used internally.

The library performs extensive compile time (TypeScript), and run time, validation of the incoming and outgoing data to ensure correctness and safety at the possible expense of raw performance. That being said, it is still extremely fast, able to round-trip process a 1,000 item tree in about 20 milliseconds.

## Security Notes

In order to help prevent the possibility of a second pre-image attack (see [^1] [^2] [^3]) the data leaf nodes provided to construct the tree are prefixed with a `0x00` byte. All inner nodes of the tree are prefixed with a `0x01` byte. These prefixes are also applied during the validation step.

An additional step that can be taken to avoid second pre-image attack vulnerability is to pre-hash your leaves *using a different hash function* (see [^3]) than the function provided to construct the tree so that `H(x) != H'(x)`. For example, use `sha3-256` to pre-hash the leaves, and use `sha2-256` to construct the tree.

This implementation is potentially vulnerable to a forgery attack for an unbalanced Merkle Tree (see [^5]), wherein, in an unbalanced Merkle Tree, the last leaf node can be duplicated to create an artificially balanced tree. This can result in the same root hash. To avoid this vulnerability, do not construct an unbalanced Merkle Trees (where the length of the `data` array provided is not a power of 2). This library provides an optional `requireBalanced` configuration flag that will throw an `Error` if the `data.length` is not a power of 2.

[^1]: [Attacking Merkle Trees With a Second Pre-image Attack](https://flawed.net.nz/2018/02/21/attacking-merkle-trees-with-a-second-preimage-attack/)
[^2]: [Merkle tree second pre-image attack](https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack)
[^3]: [What is the purpose of using different hash functions for the leaves and internals of a hash tree?](https://crypto.stackexchange.com/questions/2106/what-is-the-purpose-of-using-different-hash-functions-for-the-leaves-and-interna)
[^4]: [Tendermint `0x00` and `0x01` prefix implementation](https://github.com/tendermint/tendermint/blob/e0f8936455029a40287a69d5b0e7baa4d5864da1/crypto/merkle/hash.go#L20)
[^5]: [Bitcoin Forum > Bitcoin > Bitcoin Discussion > [Full Disclosure] CVE-2012-2459 (block merkle calculation exploit)](https://bitcointalk.org/?topic=102395)
[^6]: [Attacking Merkle Trees With a Second Pre-image Attack (Hacker News)](https://news.ycombinator.com/item?id=16572793)

## Install

```sh
npm install @truestamp/tree
```

## Sample Usage

Node.js:

```javascript
const { Tree } = require('@truestamp/tree')
// import { Tree } from '@truestamp/tree';

// A sample data array with 8 elements of 32 bytes each.
// The data elements should be the same length as the output of the hash.
const data = [
  new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]),
  new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]),
  new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]),
  new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]),
  new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]),
  new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]),
  new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]),
  new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]),
]

// Construct the Merkle tree, the hash function name and options are optional.
const t = new Tree(data, 'sha256', { requireBalanced: true, debug: false })

// Get the root of the tree for later use
const r = t.root()

// For example purposes, pick (and store a verifiable copy) of
// one data element that will be verified.
// In the real world likely store a pristine copy of the data
// for later re-hashing and verification.
const d = data[4]

// Extract the Merkle inclusion proof for that data element to store
// alongside your pristine copy of the data.
// In the real world you'd likely do the same for every data element
// to store and later verify).
const p = t.proofObject(d)

// At any time in the future, verify your proof by providing
// the stored root, the proof, and the data. The last argument, the hash
// function name, is optional in this case since we're using the
// proof object encoding.
console.log('verified?', Tree.verify(r, p, d)) // returns true or false
```

A more detailed version of this example can be found in [examples/example.cjs].

## API Documentation

The [TypeScript API documentation](https://truestamp.github.io/truestamp-tree/) for this project is generated and published upon each new release.

## Performance

Using the example code on a MacBook Pro and the following size sample data sets of random elements and the Node.js `crypto` SHA-256 function:

### `1,000` data elements

* creates a tree in `13.03ms`
* extracts the Merkle root from the tree in `0.154ms`
* extracts a single Merkle inclusion proof in `3.42ms`
* verifies that proof in `1.15ms`

### `1,000,000` data elements

* creates a tree in `3.490s`
* extracts the Merkle root from the tree in `0.204ms`
* extracts a single Merkle inclusion proof in `23.139ms`
* verifies that proof in `1.533ms`

## Testing

This library aims to maintain 100% code test coverage.

```sh
npm i
npm test
```

## Contributing

We'd love you to join our network of contributors. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) for help getting started.

### Releasing

* Commit changes, merge PR's to `main` branch
* Bump `version` field in `package.json`
* Cut a new [release](https://github.com/truestamp/truestamp-tree/releases)
* New release will trigger workflow to build, test, and publish package to
  [Github Package Registry](https://github.com/truestamp/truestamp-tree/packages)
  and [NPM.js](https://www.npmjs.com/package/@truestamp/tree).

## Code of Conduct

We expect all members of the community to respect our
[Code of Conduct](CODE_OF_CONDUCT.md) at all times.

## Legal

Copyright ?? 2022 Truestamp Inc. All Rights Reserved.
