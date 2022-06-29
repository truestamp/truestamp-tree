// Copyright © 2020-2022 Truestamp Inc. All rights reserved.

export { Tree } from './modules/tree'

export type {
  MerkleRoot,
  ProofBinary,
  ProofHex,
  ProofObjectLayer,
  ProofObject,
  TreeData,
  TreeHashFunctionName,
  TreeOptions,
  TreeTree,
  UnionProofHashTypes,
} from './modules/types'

export {
  compare,
  concat,
  decodeHex,
  encodeHex,
  powerOfTwo,
  sha224,
  sha256,
  sha384,
  sha512,
  sha512_256,
  sha3_224,
  sha3_256,
  sha3_384,
  sha3_512,
} from './modules/utils'
