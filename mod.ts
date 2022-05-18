// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

// Deno export with extension style. Enabled for this file with .vscode/settings.json:

export { Tree } from './src/modules/tree.ts'

export type {
  ProofBinary,
  ProofHex,
  ProofObjectLayer,
  ProofObject,
  TreeData,
  TreeHashFunctionName,
  TreeOptions,
  TreeTree,
} from './src/modules/types.ts'

export {
  concat,
  compare,
  encodeHex,
  decodeHex,
  powerOfTwo,
  sha224,
  sha384,
  sha256,
  sha512,
  sha512_256,
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
} from './src/modules/utils.ts'
